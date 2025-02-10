package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
)
// 配置结构体
type Config struct {
	Port         int    `mapstructure:"port"`
	InputFile    string `mapstructure:"inputFile"`
	OutputFile   string `mapstructure:"outputFile"`
	Bandwidth    string `mapstructure:"bandwidth"`
	Rate         int    `mapstructure:"rate"`
	BenchPrompt  string `mapstructure:"benchPrompt"`
	BenchTimeout string `mapstructure:"benchTimeout"`
	DisableBench bool   `mapstructure:"disableBench"`
	BenchOutputFile string `mapstructure:"benchOutputFile"`
	MaxWorkers   int    `mapstructure:"maxWorkers"`    // 最大工作协程数
}
// 全局配置
var cfg Config

// 模型列表结构体
type ModelList struct {
	Models []string `json:"models"`
}

// 生成请求结构体
type GenerateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

// 生成响应结构体
type GenerateResponse struct {
	Response string `json:"response"`
	Duration int64  `json:"total_duration"`
}

// 扫描结果结构体
type ScanResult struct {
	IP     string
	Models []ModelInfo
}

// 模型信息结构体
type ModelInfo struct {
	Name            string
	Status          string
	FirstTokenDelay time.Duration
	TokensPerSec    float64
}

// 主函数
func main() {
	loadConfig()
	for {
		fmt.Println("\n=== 主菜单 ===")
		fmt.Println("1. 检查依赖")
		fmt.Println("2. 端口扫描")
		fmt.Println("3. 检测服务")
		fmt.Println("4. 检测速度")
		fmt.Println("0. 退出")
		fmt.Print("请选择操作：")

		var choice int
		fmt.Scanln(&choice)

		switch choice {
		case 1:
			checkDependencies()
		case 2:
			startScan()
		case 3:
			checkService()
		case 4:
			benchmarkModel()
		case 0:
			os.Exit(0)
		default:
			fmt.Println("无效的选项")
		}
	}
}

// 加载配置
func loadConfig() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.WatchConfig()

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("读取配置文件失败: %v\n", err)
		os.Exit(1)
	}

	if err := viper.Unmarshal(&cfg); err != nil {
		fmt.Printf("解析配置失败: %v\n", err)
		os.Exit(1)
	}
}

// 检查依赖
func checkDependencies() {
	fmt.Println("正在检查依赖...")
	if _, err := exec.LookPath("zmap"); err != nil {
		fmt.Println("未找到zmap，正在安装...")
		cmd := exec.Command("sudo", "apt-get", "install", "-y", "zmap")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("安装zmap失败: %v\n", err)
			return
		}
		fmt.Println("zmap安装成功")
	} else {
		fmt.Println("zmap已安装")
	}
}

// 端口扫描
func startScan() {
	fmt.Println("端口扫描...")
	args := []string{
		"-p", fmt.Sprintf("%d", cfg.Port),
		"--bandwidth", cfg.Bandwidth,
		"--rate", fmt.Sprintf("%d", cfg.Rate),
		"-w", cfg.InputFile,
		"-o", "scan.csv",
	}

	cmd := exec.Command("zmap", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("执行命令: zmap %s\n", strings.Join(args, " "))
	if err := cmd.Run(); err != nil {
		fmt.Printf("扫描失败: %v\n", err)
		return
	}
	fmt.Println("扫描完成")
}

// 检查端口是否开放
func checkPort(ip string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// 检查Ollama服务并获取模型列表
func checkOllamaService(client *http.Client, ip string, port int) ([]string, error) {
	// 检查服务是否运行
	resp, err := client.Get(fmt.Sprintf("http://%s:%d", ip, port))
	if err != nil {
		return nil, fmt.Errorf("Ollama服务未运行: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("Ollama服务返回状态码: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 获取模型列表
	url := fmt.Sprintf("http://%s:%d/api/tags", ip, port)
	resp, err = client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("获取模型列表失败: %v", err)
	}
	defer resp.Body.Close()

	var data struct {
		Models []struct {
			Model string `json:"model"`
			Size  int64  `json:"size,omitempty"`
		} `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("解析模型列表失败: %v", err)
	}

	// 提取并排序模型名称
	var models []string
	modelMap := make(map[string]bool)
	for _, m := range data.Models {
		if !modelMap[m.Model] {
			models = append(models, m.Model)
			modelMap[m.Model] = true
		}
	}
	sort.Strings(models)
	
	return models, nil
}

// 检测ollama服务
func checkService() {
	fmt.Println("检测ollama服务...")
	
	file, err := os.Open("scan.csv")
	if err != nil {
		fmt.Printf("打开扫描结果文件失败: %v\n", err)
		return
	}
	defer file.Close()

	// 如果配置的worker数为0，设置默认值
	workers := cfg.MaxWorkers
	if workers <= 0 {
		workers = runtime.NumCPU() // 默认使用CPU核心数
	}
	
	// 创建工作通道
	jobs := make(chan string, workers)
	
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// 启动工作协程
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				fmt.Printf("检测 %s:%d ...\n", ip, cfg.Port)
				
				if !checkPort(ip, cfg.Port, 5*time.Second) {
					fmt.Printf("端口 %d 未开放\n", cfg.Port)
					continue
				}

				models, err := checkOllamaService(client, ip, cfg.Port)
				if err != nil {
					fmt.Printf("%s: %v\n", ip, err)
					continue
				}

				if len(models) > 0 {
					csvData := []string{
						ip,
						strings.Join(models, ";"),
					}
					mu.Lock()
					err := writeCSV(csvData)
					mu.Unlock()
					if err != nil {
						fmt.Printf("写入CSV失败: %v\n", err)
					}
				}
			}
		}()
	}

	// 读取并发送任务
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.Split(scanner.Text(), ",")[0]
		jobs <- ip
	}
	close(jobs)

	// 等待所有工作完成
	wg.Wait()

	if err := scanner.Err(); err != nil {
		fmt.Printf("扫描文件时出错: %v\n", err)
	}
}

// 对所有模型进行性能测试
func benchmarkModel() {
	fmt.Println("模型性能测试...")
	// 读取服务检测结果
	file, err := os.Open(cfg.OutputFile)
	if err != nil {
		fmt.Printf("打开服务检测文件失败: %v\n", err)
		return
	}
	defer file.Close()

	// 创建性能测试结果文件
	benchFile, err := os.Create("benchmark.csv")
	if err != nil {
		fmt.Printf("创建性能测试结果文件失败: %v\n", err)
		return
	}
	defer benchFile.Close()

	writer := csv.NewWriter(benchFile)
	defer writer.Flush()

	timeout, err := time.ParseDuration(cfg.BenchTimeout)
	if err != nil {
		fmt.Printf("解析超时时间失败: %v\n", err)
		return
	}

	client := &http.Client{
		Timeout: timeout,
	}

	// 读取每一行服务检测结果
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			continue
		}

		ip := parts[0]
		models := strings.Split(parts[1], ";")

		// 对每个模型进行性能测试
		for _, model := range models {
			fmt.Printf("测试 %s 的模型 %s\n", ip, model)
			
			url := fmt.Sprintf("http://%s:%d/api/generate", ip, cfg.Port)
			req := GenerateRequest{
				Model:  model,
				Prompt: cfg.BenchPrompt,
			}
			
			jsonData, err := json.Marshal(req)
			if err != nil {
				fmt.Printf("生成请求数据失败: %v\n", err)
				continue
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			request, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
			if err != nil {
				cancel()
				fmt.Printf("创建请求失败: %v\n", err)
				continue
			}
			request.Header.Set("Content-Type", "application/json")

			start := time.Now()
			resp, err := client.Do(request)
			firstByte := time.Since(start) // 首字节响应时间，可作为首token延迟
			if err != nil {
				cancel()
				fmt.Printf("执行请求失败: %v\n", err)
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			cancel()
			
			totalTime := time.Since(start)
			
			if err != nil {
				fmt.Printf("读取响应失败: %v\n", err)
				continue
			}

			var genResp GenerateResponse
			if err := json.Unmarshal(body, &genResp); err != nil {
				fmt.Printf("解析响应失败: %v\n", err)
				continue
			}

			tokens := len(strings.Split(genResp.Response, " "))
			tps := float64(tokens) / totalTime.Seconds()

			// 写入该模型的测试结果
			data := []string{
				ip,
				model,
				fmt.Sprintf("%d", firstByte.Milliseconds()),
				fmt.Sprintf("%.2f", tps),
			}
			if err := writer.Write(data); err != nil {
				fmt.Printf("写入性能测试结果失败: %v\n", err)
			}
			writer.Flush()
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("扫描文件时出错: %v\n", err)
	}
}

// printResult 格式化打印扫描结果
func printResult(ip string, models []string, benchResults map[string]ModelInfo) {
	fmt.Printf("\nIP地址: %s\n", ip)
	fmt.Println(strings.Repeat("-", 50))
	
	for _, model := range models {
		fmt.Printf("├─ 模型: %-25s\n", model)
		if !cfg.DisableBench {
			if benchInfo, exists := benchResults[model]; exists {
				fmt.Printf("│  ├─ 首Token延迟: %v\n", benchInfo.FirstTokenDelay.Round(time.Millisecond))
				fmt.Printf("│  └─ 生成速度: %.1f tokens/s\n", benchInfo.TokensPerSec)
			} else {
				fmt.Printf("│  └─ 未进行性能测试\n")
			}
		}
		fmt.Println(strings.Repeat("-", 50))
	}
}

// 加载性能测试结果
func loadBenchResults() map[string]map[string]ModelInfo {
	results := make(map[string]map[string]ModelInfo)
	
	file, err := os.Open("benchmark.csv")
	if err != nil {
		return results
	}
	defer file.Close()

	reader := csv.NewReader(file)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) != 4 {
			continue
		}

		ip := record[0]
		model := record[1]
		delay, _ := strconv.ParseInt(record[2], 10, 64)
		tps, _ := strconv.ParseFloat(record[3], 64)

		if _, exists := results[ip]; !exists {
			results[ip] = make(map[string]ModelInfo)
		}

		results[ip][model] = ModelInfo{
			Name:            model,
			FirstTokenDelay: time.Duration(delay) * time.Millisecond,
			TokensPerSec:    tps,
		}
	}
	
	return results
}

// 需要在检测服务或性能测试完成后调用
func displayResults() {
	file, err := os.Open(cfg.OutputFile)
	if err != nil {
		fmt.Printf("打开结果文件失败: %v\n", err)
		return
	}
	defer file.Close()

	benchResults := loadBenchResults()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ",")
		if len(parts) != 2 {
			continue
		}
		
		ip := parts[0]
		models := strings.Split(parts[1], ";")
		
		printResult(ip, models, benchResults[ip])
	}
}

// 写入CSV
func writeCSV(data []string) error {
	file, err := os.OpenFile(cfg.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("打开CSV文件失败: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write(data); err != nil {
		return fmt.Errorf("写入CSV失败: %v", err)
	}
	return nil
}
