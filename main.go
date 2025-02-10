package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"github.com/spf13/viper"
)

// 全局变量定义
var (
	// 扫描参数
	port            int       		// 扫描端口号
	inputFile       string    		// 输入文件路径
	outputFile      string    		// 输出文件路径
	bandwidth       string    		// 带宽限制
	rate            int       		// 扫描速率

	// HTTP配置参数
	timeout         time.Duration 	// 网络超时时间
	idleConnTimeout time.Duration 	// 空闲连接超时时间
	maxWorkers      int       		// 最大工作线程数
	maxIdleConns    int       		// 最大空闲连接数
	httpClient      *http.Client  	// HTTP客户端

	// 性能测试参数
	disableBench    bool      		// 是否禁用性能测试
	benchPrompt     string    		// 性能测试使用的提示词
	benchTimeout    time.Duration 	// 性能测试超时时间

	// 文件操作
	csvWriter   *csv.Writer   		// CSV写入器
	csvFile     *os.File      		// CSV文件句柄
	
	// 并发控制
	resultsChan chan ScanResult 	// 扫描结果通道
	resultPool  = sync.Pool{  		// 扫描结果对象池
		New: func() interface{} {
			return &ScanResult{}
		},
	}
)

// WorkerPool 工作协程池
type WorkerPool struct {
	workers chan struct{}
	wg      sync.WaitGroup
}

// NewWorkerPool 创建新的工作协程池
func NewWorkerPool(size int) *WorkerPool {
	return &WorkerPool{
		workers: make(chan struct{}, size),
	}
}

// Submit 提交任务到工作协程池
func (p *WorkerPool) Submit(ctx context.Context, task func()) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		select {
		case p.workers <- struct{}{}:
			task()
			<-p.workers
		case <-ctx.Done():
			return
		}
	}()
}

// Wait 等待所有任务完成
func (p *WorkerPool) Wait() {
	p.wg.Wait()
}

// main 程序入口
func main() {
	if err := checkDependencies(); err != nil {
		fmt.Printf("⚠️ Dependency check failed: %v\n", err)
		os.Exit(1)
	}

	if err := loadConfig(); err != nil {
		fmt.Printf("⚠️ Configuration error: %v\n", err)
		os.Exit(1)
	}

	if err := validateConfig(); err != nil {
		fmt.Printf("⚠️ Validation error: %v\n", err)
		os.Exit(1)
	}

	initHTTPClient()

	if err := startScan(); err != nil {
		fmt.Printf("❌ Scan failed: %v\n", err)
		os.Exit(1)
	}
}

// checkDependencies 检查依赖
func checkDependencies() error {
	fmt.Println("1. Checking zmap...")
	if _, err := exec.LookPath("zmap"); err != nil {
		fmt.Println("zmap not found, installing...")
		cmd := exec.Command("sudo", "apt", "install", "zmap", "-y")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("zmap installation failed: %v", err)
		}
		fmt.Println("✅ zmap installation successful")
	}

	return nil
}

// validateConfig 验证配置
func validateConfig() error {
	port = viper.GetInt("port")
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port number: %d", port)
	}

	inputFile = viper.GetString("inputFile")
	outputFile = viper.GetString("outputFile")
	if inputFile == "" || outputFile == "" {
		return fmt.Errorf("input or output file path cannot be empty")
	}

	rate = viper.GetInt("rate")
	if rate <= 0 {
		return fmt.Errorf("scan rate must be greater than 0")
	}

	disableBench = viper.GetBool("disableBench")
	benchPrompt = viper.GetString("benchPrompt")
	if !disableBench && benchPrompt == "" {
		return fmt.Errorf("benchmark prompt cannot be empty when performance testing is enabled")
	}

	return nil
}

// loadConfig 加载配置文件
func loadConfig() error {
	viper.SetConfigName("config")  
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	viper.SetDefault("port", 11434)
	viper.SetDefault("inputFile", "ip.txt")  
	viper.SetDefault("outputFile", "results.csv") 
	viper.SetDefault("rate", 10000)
	viper.SetDefault("bandwidth", "30M")

	viper.SetDefault("timeout", "3s")
	viper.SetDefault("idleConnTimeout", "90s")
	viper.SetDefault("maxWorkers", runtime.NumCPU()*10)
	viper.SetDefault("maxIdleConns", runtime.NumCPU()*2)

	viper.SetDefault("disableBench", false)
	viper.SetDefault("benchPrompt", "用一句话自我介绍")
	viper.SetDefault("benchTimeout", "30s")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("failed to read config file: %v", err)
		}
	}

	resultsChan = make(chan ScanResult, maxWorkers)

	return nil
}

// initHTTPClient 初始化HTTP客户端
func initHTTPClient() {
    httpClient = &http.Client{
        Timeout: timeout,
        Transport: &http.Transport{
            MaxIdleConns:        maxIdleConns,
            IdleConnTimeout:     idleConnTimeout,
            DisableKeepAlives:   false,
            MaxConnsPerHost:     maxWorkers / 2,
            MaxIdleConnsPerHost: maxWorkers / 4,
        },
    }
}

// startScan 启动扫描
func startScan() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	initCSVWriter()
	defer func() {
		if csvFile != nil {
			csvFile.Close()
		}
	}()

	setupSignalHandler(cancel)

	return runScanProcess(ctx)
}

// initCSVWriter 初始化CSV写入器
func initCSVWriter() error {
	var err error
	csvFile, err = os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %v", err)
	}

	csvWriter = csv.NewWriter(csvFile)
	headers := []string{"IP address", "Port", "Model name", "Status"}
	if !disableBench {
		headers = append(headers, "First token delay (ms)", "Tokens/s")
	}
	return csvWriter.Write(headers)
}

// setupSignalHandler 设置信号处理
func setupSignalHandler(cancel context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
		fmt.Println("\n🛑 Received termination signal, cleaning up resources...")
		if csvWriter != nil {
			csvWriter.Flush()
		}
		os.Exit(1)
	}()
}

// runScanProcess 运行扫描过程
func runScanProcess(ctx context.Context) error {
	fmt.Println("\nFirst stage: Port scanning")
	if err := execZmap(); err != nil {
		return err
	}

	if !portScanOnly {
		fmt.Println("\nSecond stage: Ollama service detection")
		if err := processResults(ctx); err != nil {
			return err
		}
	}
	
	return nil
}

// execZmap 执行Zmap扫描
func execZmap() error {
	args := []string{
		"zmap",
		"-p", fmt.Sprintf("%d", port),
		"-w", inputFile,
		"-o", outputFile,
		"-B", bandwidth,
		"--rate", fmt.Sprintf("%d", rate),
	}

	fmt.Printf("Executing command: %s\n", strings.Join(args, " "))
	
	cmd := exec.Command(args[0], args[1:]...)
	
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// processResults 处理扫描结果
func processResults(ctx context.Context) error {
	file, err := os.Open(outputFile)
	if err != nil {
		return fmt.Errorf("failed to open result file: %w", err)
	}
	defer file.Close()

	pool := NewWorkerPool(maxWorkers)
	
	go resultHandler()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if net.ParseIP(ip) != nil {
			pool.Submit(ctx, func() {
				processIP(ctx, ip)
			})
		}
	}

	pool.Wait()
	close(resultsChan)
	
	csvWriter.Flush()
	fmt.Printf("\n✅ Results saved to %s\n", outputFile)
	return nil
}

// resultHandler 处理结果
func resultHandler() {
	for res := range resultsChan {
		printResult(res)
		writeCSV(res)
	}
}

// printResult 打印结果
func printResult(res ScanResult) {
	fmt.Printf("\nIP address: %s\n", res.IP)
	fmt.Println(strings.Repeat("-", 50))
	for _, model := range res.Models {
		fmt.Printf("├─ Model: %-25s\n", model.Name)
		if !disableBench {
			fmt.Printf("│  ├─ Status: %s\n", model.Status)
			fmt.Printf("│  ├─ First token delay: %v\n", model.FirstTokenDelay.Round(time.Millisecond))
			fmt.Printf("│  └─ Tokens per second: %.1f\n", model.TokensPerSec)
		} else {
			fmt.Printf("│  └─ Status: %s\n", model.Status)
		}
		fmt.Println(strings.Repeat("-", 50))
	}
}

// writeCSV 将扫描结果写入CSV文件
func writeCSV(res ScanResult) {
	for _, model := range res.Models {
		record := []string{res.IP, fmt.Sprintf("%d", port), model.Name, model.Status}
		if !disableBench {
			record = append(record,
				fmt.Sprintf("%.0f", model.FirstTokenDelay.Seconds()*1000),
				fmt.Sprintf("%.1f", model.TokensPerSec),
			)
		}
		csvWriter.Write(record)
	}
}

// worker 工作协程，处理IP地址扫描任务
func worker(ctx context.Context, wg *sync.WaitGroup, ips <-chan string) {
	defer wg.Done()
	for ip := range ips {
		processIP(ctx, ip)
	}
}

// checkPort 检查IP的端口是否开放
func checkPort(ip string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// checkOllama 检查IP是否运行Ollama服务
func checkOllama(ip string) bool {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:%d/api/tags", ip, port), nil)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	defer resp.Body.Close()
	
	var response struct{ Models []interface{} }
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return false
	}
	return len(response.Models) > 0
}

// getModels 获取模型列表
func getModels(ip string) []string {
	url := fmt.Sprintf("http://%s:%d/api/tags", ip, port)
	
	resp, err := httpClient.Get(url)
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

// sortModels 对模型列表进行排序
func sortModels(models []string) []string {
	sort.Strings(models)
	return models
}

// benchmarkModel 对模型进行性能测试
func benchmarkModel(ip, model string) (time.Duration, float64, string) {
	ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
	defer cancel()

	payload := map[string]interface{}{
		"model":  model,
		"prompt": benchPrompt,
		"stream": true,
	}

	body, _ := json.Marshal(payload)
	
	req, _ := http.NewRequestWithContext(ctx, "POST", 
		fmt.Sprintf("http://%s:%d/api/generate", ip, port),
		bytes.NewReader(body))

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, 0, "Connection failed"
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
		return 0, 0, "No response data"
	}

	totalTime := lastToken.Sub(firstToken).Seconds()
	if totalTime == 0 {
		return 0, 0, "Zero time interval"
	}
	tokensPerSec := float64(tokenCount) / totalTime

	return firstToken.Sub(time.Time{}), tokensPerSec, "Success"
}
