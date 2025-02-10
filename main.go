package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	// 导入viper读取配置
	"github.com/spf13/viper"
)

// 配置结构体
type Config struct {
    // zmap 扫描相关配置    
    Port            int           `mapstructure:"port"`
    InputFile       string        `mapstructure:"inputFile"` 
    OutputFile      string        `mapstructure:"outputFile"`
    Rate            int           `mapstructure:"rate"`
    Bandwidth       string        `mapstructure:"bandwidth"`

    // ollama 检测服务相关配置
    MaxWorkers      int           `mapstructure:"maxWorkers"`
    MaxIdleConns    int           `mapstructure:"maxIdleConns"`
    Timeout         time.Duration `mapstructure:"timeout"`
    IdleConnTimeout time.Duration `mapstructure:"idleConnTimeout"`

    // ollama 性能测试相关配置
    BenchPrompt     string        `mapstructure:"benchPrompt"`
    BenchTimeout    time.Duration `mapstructure:"benchTimeout"`

    // 中间文件配置
    ScanOutputFile    string        `mapstructure:"scanOutputFile"`    // zmap扫描结果
    OllamaOutputFile  string        `mapstructure:"ollamaOutputFile"`  // ollama服务检测结果
}

// 扫描结果结构体
type ScanResult struct {
    IP              string        // IP地址
    Name            string        // 模型名称 
    Status          string        // 状态
    FirstTokenDelay time.Duration // 首Token延迟时间
    TokensPerSec    float64       // 每秒生成Token数量
}

// 扫描器结构体
type Scanner struct {
    cfg          *Config
    httpClient   *http.Client
    csvWriter    *csv.Writer
    csvFile      *os.File
    resultsChan  chan ScanResult
    resultPool   sync.Pool
}

func init() {
    // 设置配置文件名
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(".")
    
    // 设置zmap 默认值
    viper.SetDefault("port", 11434)
    viper.SetDefault("inputFile", "ips.txt")
    viper.SetDefault("outputFile", "results.csv") 
    viper.SetDefault("rate", 10000)
    viper.SetDefault("bandwidth", "100M")
    
    // 设置ollama默认值
    viper.SetDefault("maxWorkers", 100)
    viper.SetDefault("maxIdleConns", 100)
    viper.SetDefault("timeout", "5s")
    viper.SetDefault("idleConnTimeout", "90s")
    
    // 设置ollama性能测试默认值
    viper.SetDefault("benchTimeout", "30s")
    viper.SetDefault("benchPrompt", "用一句话自我介绍")

    // 设置中间文件默认值
    viper.SetDefault("scanOutputFile", "ip.csv")
    viper.SetDefault("ollamaOutputFile", "ollama.csv") 

    // 读取配置文件
    if err := viper.ReadInConfig(); err != nil {
        fmt.Printf("⚠️ 配置文件读取失败: %v\n", err)
    }
}

// 主函数
func main() {
	scanner, err := NewScanner()
	if err != nil {
		fmt.Printf("❌ 初始化失败: %v\n", err)
		os.Exit(1)
	}

	for {
		fmt.Println("\n请选择操作:")
		fmt.Println("1. 扫描IP地址")
		fmt.Println("2. 检测Ollama服务")
		fmt.Println("3. 性能测试")
		fmt.Println("4. 退出")
		
		var choice int
		fmt.Print("请输入选项(1-4): ")
		fmt.Scan(&choice)
		
		switch choice {
		case 1:
			if err := scanner.ScanIPs(); err != nil {
				fmt.Printf("❌ IP扫描失败: %v\n", err)
				continue
			}
			fmt.Printf("✅ IP扫描完成，结果已保存至 %s\n", scanner.cfg.ScanOutputFile)
			
		case 2:
			if err := scanner.DetectOllama(); err != nil {
				fmt.Printf("❌ Ollama服务检测失败: %v\n", err)
				continue
			}
			fmt.Printf("✅ 服务检测完成，结果已保存至 %s\n", scanner.cfg.OllamaOutputFile)
			
		case 3:
			if err := scanner.BenchmarkOllama(); err != nil {
				fmt.Printf("❌ 性能测试失败: %v\n", err)
				continue
			}
			fmt.Printf("✅ 性能测试完成，结果已保存至 %s\n", scanner.cfg.OutputFile)
			
		case 4:
			fmt.Println("👋 再见!")
			return
			
		default:
			fmt.Println("❌ 无效的选项，请重新选择")
		}
	}
}

// 加载配置
func (s *Scanner) loadConfig() *Config {
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("⚠️ 配置文件读取失败: %v\n", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		fmt.Printf("⚠️ 配置解析失败: %v\n", err)
	}
	return &cfg
}

// 初始化扫描器
func NewScanner() (*Scanner, error) {
	// 创建scanner实例
	scanner := &Scanner{}
	
	// 使用scanner的loadConfig方法
	cfg := scanner.loadConfig()
	
	// 创建 CSV 文件
	csvFile, err := os.Create(cfg.OutputFile)
	if err != nil {
		return nil, fmt.Errorf("创建CSV文件失败: %w", err)
	}
	
	// 创建 HTTP 客户端
	httpClient := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			MaxIdleConns: cfg.MaxIdleConns,
			IdleConnTimeout: cfg.IdleConnTimeout,
		},
	}
	
	// 设置scanner的其他字段
	scanner.cfg = cfg
	scanner.httpClient = httpClient
	scanner.csvFile = csvFile
	scanner.csvWriter = csv.NewWriter(csvFile)
	scanner.resultsChan = make(chan ScanResult, cfg.MaxWorkers*2)
	scanner.resultPool = sync.Pool{
		New: func() interface{} { return &ScanResult{} },
	}
	
	return scanner, nil
}

// 运行扫描器
func (s *Scanner) Run() error {
	defer func() {
		s.csvWriter.Flush()
		s.csvFile.Close()
	}()
	
	// 写入CSV头
	s.csvWriter.Write([]string{"IP地址", "端口", "模型名称", "状态", "首Token延迟(ms)", "Tokens/s"})
	
	if err := s.execZmap(); err != nil {
		return err
	}
	return s.processResults(context.Background())
}

// 扫描端口并写入结果
func (s *Scanner) execZmap() error {
	tmpFile, err := os.CreateTemp("", "zmap-result-*.txt") 
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	cmd := exec.Command("sudo", "zmap",
		"-w", s.cfg.InputFile,
		"-o", s.cfg.OutputFile,
		"-p", strconv.Itoa(s.cfg.Port),
		"--rate", strconv.Itoa(s.cfg.Rate),
		"-B", s.cfg.Bandwidth,
	)

	return cmd.Run()
}
// 解析IP列表
func (s *Scanner) parseIPs() ([]string, error) {
	ips, err := os.ReadFile(s.cfg.InputFile)
	if err != nil {
		return nil, fmt.Errorf("读取IP文件失败: %w", err)
	}
	return strings.Split(string(ips), "\n"), nil
}

// 对IP列表进行 checkOllama 服务检测
func (s *Scanner) processResults(ctx context.Context) error {
    // 从文件读取IP列表
    ips, err := s.parseIPs()
    if err != nil || len(ips) == 0 {
        return fmt.Errorf("未找到有效IP地址")
    }
    
    fmt.Printf("共发现 %d 个有效IP地址\n", len(ips))
    
    // 创建工作池
    workerPool := make(chan struct{}, s.cfg.MaxWorkers)
    var wg sync.WaitGroup
    
    // 启动结果处理协程
    go s.handleResults(s.resultsChan)
    
    // 分发任务给工作协程
    for _, ip := range ips {
        workerPool <- struct{}{} // 获取工作槽
        wg.Add(1)
        
        go func(ip string) {
            defer func() {
                <-workerPool // 释放工作槽
                wg.Done()
            }()
            
            if s.checkOllama(ip) {
                s.processModels(ip)
            }
        }(ip)
    }
    
    // 等待所有工作完成
    wg.Wait()
    close(s.resultsChan)
    
    return nil
}

// 检测ollama服务
func (s *Scanner) checkOllama(ip string) bool {
	resp, err := s.httpClient.Get(fmt.Sprintf("http://%s:%d", ip, s.cfg.Port))
	if err != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	defer resp.Body.Close()

	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	return strings.Contains(string(buf[:n]), "Ollama is running")
}

// 获取模型
func (s *Scanner) getModels(ip string) []string {
	url := fmt.Sprintf("http://%s:%d/api/tags", ip, s.cfg.Port)
	
	resp, err := s.httpClient.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	defer resp.Body.Close()

	var data struct {
		Models []struct {
			Model string `json:"model"`
		} `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}

	var models []string
	for _, m := range data.Models {
		models = append(models, m.Model)
	}
	
	return models
}

// 处理单个IP的模型
func (s *Scanner) processModels(ip string) {
    // 获取该IP上的所有模型
    models := s.getModels(ip)
    if len(models) == 0 {
        return
    }
    
    // 对每个模型进行性能测试
    for _, model := range models {
        // 从对象池获取结果对象
        result := s.resultPool.Get().(*ScanResult)
        result.IP = ip
        result.Name = model
        
        // 进行性能测试
        latency, tps, status := s.benchmarkModel(ip, model)
        result.FirstTokenDelay = latency
        result.TokensPerSec = tps
        result.Status = status
        
        // 发送结果并回收对象
        s.resultsChan <- *result
        s.resultPool.Put(result)
    }
}

// 性能测试
func (s *Scanner) benchmarkModel(ip, model string) (time.Duration, float64, string) {
	start := time.Now()
	
	payload := map[string]interface{}{
		"model":  model,
		"prompt": s.cfg.BenchPrompt,
		"stream": true,
	}

	body, _ := json.Marshal(payload)
	
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("http://%s:%d/api/generate", ip, s.cfg.Port),
		bytes.NewReader(body))

	client := &http.Client{Timeout: s.cfg.BenchTimeout}
	
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, "连接失败"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var (
		firstToken time.Time
		lastToken  time.Time
		tokenCount int
	)

	for scanner.Scan() {
		if tokenCount == 0 {
			firstToken = time.Now()
		}
		lastToken = time.Now()
		tokenCount++

		var data map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &data); err != nil {
			continue
		}

		if done, _ := data["done"].(bool); done {
			break
		}
	}

	if tokenCount == 0 {
		return 0, 0, "无响应"
	}

	totalTime := lastToken.Sub(start)
	
	return firstToken.Sub(start), float64(tokenCount) / totalTime.Seconds(), "成功"
}

// 处理结果
func (s *Scanner) handleResults(results <-chan ScanResult) {
    for result := range results {
        // 写入CSV记录
        s.csvWriter.Write([]string{
            result.IP,
            strconv.Itoa(s.cfg.Port),
            result.Name,
            result.Status,
            strconv.FormatFloat(result.FirstTokenDelay.Seconds()*1000, 'f', 0, 64),
            strconv.FormatFloat(result.TokensPerSec, 'f', 1, 64),
        })
        s.csvWriter.Flush()
    }
}

// 扫描IP地址
func (s *Scanner) ScanIPs() error {
    // 创建CSV文件
    csvFile, err := os.Create(s.cfg.ScanOutputFile)
    if err != nil {
        return fmt.Errorf("创建CSV文件失败: %w", err)
    }
    defer csvFile.Close()
    
    writer := csv.NewWriter(csvFile)
    defer writer.Flush()
    
    // 写入CSV头
    writer.Write([]string{"IP地址", "端口"})
    
    // 执行zmap扫描
    return s.execZmap()
}

// 检测Ollama服务
func (s *Scanner) DetectOllama() error {
    // 读取扫描结果
    ips, err := s.parseIPs()
    if err != nil {
        return err
    }
    
    // 创建CSV文件
    csvFile, err := os.Create(s.cfg.OllamaOutputFile)
    if err != nil {
        return fmt.Errorf("创建CSV文件失败: %w", err)
    }
    defer csvFile.Close()
    
    writer := csv.NewWriter(csvFile)
    defer writer.Flush()
    
    // 写入CSV头
    writer.Write([]string{"IP地址", "端口", "状态"})
    
    // 创建工作池检测服务
    workerPool := make(chan struct{}, s.cfg.MaxWorkers)
    var wg sync.WaitGroup
    
    for _, ip := range ips {
        workerPool <- struct{}{}
        wg.Add(1)
        
        go func(ip string) {
            defer func() {
                <-workerPool
                wg.Done()
            }()
            
            status := "未发现服务"
            if s.checkOllama(ip) {
                status = "服务正常"
            }
            
            writer.Write([]string{
                ip,
                strconv.Itoa(s.cfg.Port),
                status,
            })
        }(ip)
    }
    
    wg.Wait()
    return nil
}

// 性能测试
func (s *Scanner) BenchmarkOllama() error {
    // 读取服务检测结果
    file, err := os.Open(s.cfg.OllamaOutputFile)
    if err != nil {
        return fmt.Errorf("读取服务检测结果失败: %w", err)
    }
    defer file.Close()
    
    reader := csv.NewReader(file)
    // 跳过CSV头
    reader.Read()
    
    // 创建结果文件
    resultFile, err := os.Create(s.cfg.OutputFile)
    if err != nil {
        return fmt.Errorf("创建结果文件失败: %w", err)
    }
    defer resultFile.Close()
    
    writer := csv.NewWriter(resultFile)
    defer writer.Flush()
    
    // 写入CSV头
    writer.Write([]string{"IP地址", "端口", "模型名称", "状态", "首Token延迟(ms)", "Tokens/s"})
    
    // 读取并处理每一行
    for {
        record, err := reader.Read()
        if err != nil {
            break
        }
        
        ip := record[0]
        if record[2] == "服务正常" {
            s.processModels(ip)
        }
    }
    
    return nil
}
