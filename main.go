package main

import (
	"bufio"
	"bytes"
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
	"net"
	// 导入viper读取配置
	"github.com/spf13/viper"
)

// 配置结构体
type Config struct {
    // zmap 扫描相关配置    
    Port           int           `mapstructure:"port"`
    InputFile      string        `mapstructure:"inputFile"` 
    OutputFile     string        `mapstructure:"outputFile"`
    Rate           int           `mapstructure:"rate"`
    Bandwidth      string        `mapstructure:"bandwidth"`

    // ollama 检测服务相关配置
    MaxWorkers     int           `mapstructure:"maxWorkers"`
    MaxIdleConns   int           `mapstructure:"maxIdleConns"`
    Timeout        time.Duration `mapstructure:"timeout"`
    IdleConnTimeout time.Duration `mapstructure:"idleConnTimeout"`

    // ollama 性能测试相关配置
    BenchPrompt    string        `mapstructure:"benchPrompt"`
    BenchTimeout   time.Duration `mapstructure:"benchTimeout"`

    // 中间文件配置
    ScanOutputFile   string        `mapstructure:"scanOutputFile"`
    OllamaOutputFile string        `mapstructure:"ollamaOutputFile"`
}

// 扫描结果结构体
type ScanResult struct {
    IP             string
    Status         string
    Models         []string
    FirstTokenDelay time.Duration
    TokensPerSec    float64
}

// 扫描器结构体
type Scanner struct {
    cfg        *Config
    httpClient *http.Client
    csvWriter  *csv.Writer
    csvFile    *os.File
    outputFile string
    mu         sync.Mutex
}

// 初始化方法
func NewScanner(operation string) (*Scanner, error) {
    scanner := &Scanner{}
    cfg := scanner.loadConfig()
    scanner.cfg = cfg // 统一加载配置
    
    // 根据操作类型设置输出文件
    switch operation {
    case "scan":
        scanner.outputFile = cfg.ScanOutputFile
        return scanner, nil
    case "detect":
        scanner.outputFile = cfg.OllamaOutputFile
    case "benchmark":
        scanner.outputFile = cfg.OutputFile
    default:
        return nil, fmt.Errorf("未知操作类型")
    }

    // 统一创建CSV文件
    if err := scanner.createCSVFile(operation); err != nil {
        return nil, err
    }

    // 按需创建HTTP客户端（仅检测和性能测试需要）
    if operation != "scan" {
        scanner.httpClient = &http.Client{
            Timeout: cfg.Timeout,
            Transport: &http.Transport{
                MaxIdleConns:    cfg.MaxIdleConns,
                IdleConnTimeout: cfg.IdleConnTimeout,
            },
        }
    }

    return scanner, nil
}

// 配置加载
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

// 资源创建
func (s *Scanner) createCSVFile(operation string) error {
    var headers []string
    switch operation {
    case "detect":
        headers = []string{"IP地址", "模型名称"}
    case "benchmark":
        headers = []string{"IP地址", "模型名称", "状态", "首Token延迟(ms)", "Tokens/s"}
    }

    file, err := os.Create(s.outputFile)
    if err != nil {
        return fmt.Errorf("创建CSV文件失败: %w", err)
    }

    writer := csv.NewWriter(file)
    if err := writer.Write(headers); err != nil {
        file.Close()
        return fmt.Errorf("写入表头失败: %w", err)
    }
    writer.Flush()

    s.csvFile = file
    s.csvWriter = writer
    return nil
}

// 资源清理
func (s *Scanner) Close() error {
    if s.csvFile != nil {
        s.csvWriter.Flush()
        return s.csvFile.Close()
    }
    return nil
}

// 扫描IP地址
func (s *Scanner) ScanIPs() error {
    // 构建 zmap 命令参数
    cmd := exec.Command("sudo", "zmap",
        "-w", s.cfg.InputFile,
        "-o", s.cfg.ScanOutputFile,
        "-p", strconv.Itoa(s.cfg.Port),
        "--rate", strconv.Itoa(s.cfg.Rate),
        "-B", s.cfg.Bandwidth,
    )
    
    // 打印完整命令
    fmt.Printf("执行命令: %s\n", strings.Join(cmd.Args, " "))
    
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    
    // 执行扫描命令
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("zmap执行失败: %w", err)
    }
    
    return nil
}

// 获取模型名称
func (s *Scanner) getModels(ip string) []string {
    var models []string
    modelsResp, err := s.httpClient.Get(fmt.Sprintf("http://%s:%d/api/tags", ip, s.cfg.Port))
    if err != nil || modelsResp.StatusCode != http.StatusOK {
        return models
    }
    defer modelsResp.Body.Close()
    var data struct {
        Models []struct {
            Model string `json:"name"`
        } `json:"models"`
    }
    
    if err := json.NewDecoder(modelsResp.Body).Decode(&data); err == nil {
        for _, m := range data.Models {
            models = append(models, m.Model)
        }
    }
    return models
}

// 服务检测
func (s *Scanner) DetectOllama() error {
    ipsData, err := os.ReadFile(s.cfg.ScanOutputFile)
    if err != nil {
        return fmt.Errorf("读取IP文件失败: %w", err)
    }
    ips := strings.Split(string(ipsData), "\n")
    
    if len(ips) == 0 {
        return fmt.Errorf("未找到有效IP地址")
    }
    
    workerPool := make(chan struct{}, s.cfg.MaxWorkers)
    var wg sync.WaitGroup
    var writeMu sync.Mutex
    
    for _, ip := range ips {
        ip = strings.TrimSpace(ip)
        if ip == "" {
            continue
        }
        
        workerPool <- struct{}{}
        wg.Add(1)
        
        go func(ip string) {
            defer func() {
                <-workerPool
                wg.Done()
            }()

            // 直接通过获取模型列表API检测服务
            models := s.getModels(ip)
            if len(models) > 0 {
                fmt.Printf("✅ 发现可用服务: %s:%d 模型列表: %v\n", 
                    ip, 
                    s.cfg.Port,
                    models)
            }
            writeMu.Lock()
            defer writeMu.Unlock()
            
            if len(models) > 0 {
                records := make([][]string, len(models))
                for i, model := range models {
                    records[i] = []string{
                        ip,
                        model,
                    }
                }
                s.csvWriter.WriteAll(records)
            }
            s.csvWriter.Flush()
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
    
    workerPool := make(chan struct{}, s.cfg.MaxWorkers)
    var wg sync.WaitGroup
    var writeMu sync.Mutex
    for {
        record, err := reader.Read()
        if err != nil {
            break
        }
        
        if len(record) < 4 {
            fmt.Printf("⚠️ 无效记录: %v\n", record)
            continue
        }
        ip := record[0]
        modelName := record[3]
        
        workerPool <- struct{}{}
        wg.Add(1)
        
        go func(ip, modelName string) {
            defer func() {
                <-workerPool
                wg.Done()
            }()
            if net.ParseIP(ip) == nil || modelName == "" {
                return
            }

            start := time.Now()
            payload := map[string]interface{}{
                "model":  modelName,
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
                writeMu.Lock()
                defer writeMu.Unlock()
                
                s.csvWriter.Write([]string{
                    ip,
                    modelName,
                    "连接失败",
                    "0",
                    "0",
                })
                return
            }

            if resp.StatusCode != http.StatusOK {
                writeMu.Lock()
                defer writeMu.Unlock()
                
                s.csvWriter.Write([]string{
                    ip,
                    modelName,
                    fmt.Sprintf("HTTP %d", resp.StatusCode),
                    "0",
                    "0",
                })
                resp.Body.Close()
                return
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
            resp.Body.Close()

            if tokenCount == 0 {
                writeMu.Lock()
                defer writeMu.Unlock()
                
                s.csvWriter.Write([]string{
                    ip,
                    modelName,
                    "无响应",
                    "0",
                    "0",
                })
                return
            }

            totalTime := lastToken.Sub(start)
            latency := firstToken.Sub(start)
            tps := float64(tokenCount) / totalTime.Seconds()

            writeMu.Lock()
            defer writeMu.Unlock()
            
            s.csvWriter.Write([]string{
                ip,
                modelName,
                "成功",
                strconv.FormatInt(latency.Milliseconds(), 10),
                fmt.Sprintf("%.2f", tps),
            })
            // 打印成功测试结果
            fmt.Printf("✅ 成功测试: %s %s %dms %f\n", 
                ip, 
                modelName,
                latency.Milliseconds(),
                tps)
            s.csvWriter.Flush()
        }(ip, modelName)
    }
    
    wg.Wait()
    return nil
}

// 主函数
func main() {
    for {
        fmt.Println("\n请选择操作:")
        fmt.Println("1. 端口扫描")
        fmt.Println("2. 服务检测")
        fmt.Println("3. 性能测试")
        fmt.Println("0. 退出程序")
        
        var choice int
        fmt.Print("请输入选项(0-3): ")
        fmt.Scan(&choice)
        
        switch choice {
        case 1:
            scanner, err := NewScanner("scan")
            if err != nil {
                fmt.Printf("❌ 初始化失败: %v\n", err)
                continue
            }
            if err := scanner.ScanIPs(); err != nil {
                fmt.Printf("❌ IP扫描失败: %v\n", err)
                continue
            }
            fmt.Printf("✅ IP扫描完成，结果已保存至 %s\n", scanner.cfg.ScanOutputFile)
            
        case 2:
            scanner, err := NewScanner("detect")
            if err != nil {
                fmt.Printf("❌ 初始化失败: %v\n", err)
                continue
            }
            if err := scanner.DetectOllama(); err != nil {
                fmt.Printf("❌ Ollama服务检测失败: %v\n", err)
                continue
            }
            fmt.Printf("✅ 服务检测完成，结果已保存至 %s\n", scanner.cfg.OllamaOutputFile)
            
        case 3:
            scanner, err := NewScanner("benchmark")
            if err != nil {
                fmt.Printf("❌ 初始化失败: %v\n", err)
                continue
            }
            if err := scanner.BenchmarkOllama(); err != nil {
                fmt.Printf("❌ 性能测试失败: %v\n", err)
                continue
            }
            fmt.Printf("✅ 性能测试完成，结果已保存至 %s\n", scanner.cfg.OutputFile)
            
        case 0:
            fmt.Println("👋 再见!")
            return
            
        default:
            fmt.Println("❌ 无效的选项，请重新选择")
        }
    }
}

// 配置初始化
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
