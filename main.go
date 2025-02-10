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
	MaxWorkers   int    `mapstructure:"maxWorkers"`
}

// API相关结构体
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

// Worker接口
type Worker interface {
	Process() error
}

// WorkerPool表示一个工作池
type WorkerPool struct {
	maxWorkers int
	jobs       chan Worker
	wg         sync.WaitGroup
	mu         sync.Mutex
}

// 服务检测任务
type ServiceCheckWorker struct {
	ip     string
	port   int
	client *http.Client
	models []string
}

// 性能测试任务
type BenchmarkWorker struct {
	ip       string
	model    string
	port     int
	client   *http.Client
	prompt   string
	writer   *csv.Writer
}

// ModelInfo 结构体定义
type ModelInfo struct {
	FirstTokenDelay time.Duration
	TokensPerSec    float64
}

// 全局配置
var cfg Config

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

// WorkerPool相关方法
func NewWorkerPool(maxWorkers int) *WorkerPool {
	if maxWorkers <= 0 {
		maxWorkers = runtime.NumCPU()
	}
	
	return &WorkerPool{
		maxWorkers: maxWorkers,
		jobs:       make(chan Worker, maxWorkers),
	}
}

func (p *WorkerPool) Start(handler func(Worker) error) {
	for i := 0; i < p.maxWorkers; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for job := range p.jobs {
				if err := handler(job); err != nil {
					fmt.Printf("处理任务失败: %v\n", err)
				}
			}
		}()
	}
}

func (p *WorkerPool) Submit(job Worker) {
	p.jobs <- job
}

func (p *WorkerPool) Wait() {
	close(p.jobs)
	p.wg.Wait()
}

func (p *WorkerPool) Lock() {
	p.mu.Lock()
}

func (p *WorkerPool) Unlock() {
	p.mu.Unlock()
}

// 依赖检查相关函数
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

// 端口扫描相关函数
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

// 服务检测相关函数
func (w *ServiceCheckWorker) Process() error {
	fmt.Printf("检测 %s:%d ...\n", w.ip, w.port)
	
	if !checkPort(w.ip, w.port, 5*time.Second) {
		fmt.Printf("端口 %d 未开放\n", w.port)
		return nil
	}

	models, err := checkOllamaService(w.client, w.ip, w.port)
	if err != nil {
		return fmt.Errorf("%s: %v", w.ip, err)
	}

	if len(models) > 0 {
		w.models = models
		benchResults := loadBenchResults()
		printResult(w.ip, models, benchResults[w.ip])
		
		for _, model := range models {
			csvData := []string{w.ip, model}
			if err := writeCSV(csvData); err != nil {
				return fmt.Errorf("写入CSV失败: %v", err)
			}
		}
	}
	return nil
}

func checkPort(ip string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// 服务检测的核心逻辑
func checkOllamaService(client *http.Client, ip string, port int) ([]string, error) {
	if !checkPort(ip, port, 5*time.Second) {
		return nil, fmt.Errorf("端口 %d 未开放", port)
	}
	
	// 获取模型列表
	models, err := getOllamaModels(client, ip, port)
	if err != nil {
		return nil, err
	}
	
	return models, nil
}

// 独立的模型列表获取函数
func getOllamaModels(client *http.Client, ip string, port int) ([]string, error) {
	// 检查服务是否运行
	if err := pingOllamaService(client, ip, port); err != nil {
		return nil, err
	}
	
	// 获取模型列表的逻辑...
	url := fmt.Sprintf("http://%s:%d/api/tags", ip, port)
	resp, err := client.Get(url)
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

// 服务可用性检查
func pingOllamaService(client *http.Client, ip string, port int) error {
	resp, err := client.Get(fmt.Sprintf("http://%s:%d", ip, port))
	if err != nil {
		return fmt.Errorf("Ollama服务未运行: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Ollama服务返回状态码: %d", resp.StatusCode)
	}
	return nil
}

// 性能测试相关函数
func (w *BenchmarkWorker) Process() error {
	fmt.Printf("测试 %s 的模型 %s\n", w.ip, w.model)
	
	url := fmt.Sprintf("http://%s:%d/api/generate", w.ip, w.port)
	req := GenerateRequest{
		Model:  w.model,
		Prompt: w.prompt,
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("生成请求数据失败: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), w.client.Timeout)
	defer cancel()
	
	request, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := w.client.Do(request)
	firstByte := time.Since(start)
	if err != nil {
		return fmt.Errorf("执行请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	totalTime := time.Since(start)
	
	if err != nil {
		return fmt.Errorf("读取响应失败: %v", err)
	}

	var genResp GenerateResponse
	if err := json.Unmarshal(body, &genResp); err != nil {
		return fmt.Errorf("解析响应失败: %v", err)
	}

	tokens := len(strings.Split(genResp.Response, " "))
	tps := float64(tokens) / totalTime.Seconds()

	data := []string{
		w.ip,
		w.model, 
		fmt.Sprintf("%d", firstByte.Milliseconds()),
		fmt.Sprintf("%.2f", tps),
	}

	if err := w.writer.Write(data); err != nil {
		return fmt.Errorf("写入性能测试结果失败: %v", err)
	}
	w.writer.Flush()
	
	return nil
}

func loadBenchResults() map[string]map[string]ModelInfo {
	results := make(map[string]map[string]ModelInfo)
	
	file, err := os.Open("benchmark.csv")
	if err != nil {
		return results
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ",")
		if len(parts) != 4 {
			continue
		}

		ip := parts[0]
		model := parts[1]
		firstTokenDelay, _ := strconv.ParseInt(parts[2], 10, 64)
		tps, _ := strconv.ParseFloat(parts[3], 64)

		if _, exists := results[ip]; !exists {
			results[ip] = make(map[string]ModelInfo)
		}

		results[ip][model] = ModelInfo{
			FirstTokenDelay: time.Duration(firstTokenDelay) * time.Millisecond,
			TokensPerSec:    tps,
		}
	}

	return results
}


// 检测ollama服务
func checkService() {
	fmt.Println("检测ollama服务...")
	
	scanner, cleanup, err := prepareScanner("scan.csv")
	if err != nil {
		fmt.Printf("准备扫描器失败: %v\n", err)
		return
	}
	defer cleanup()
	
	pool := NewWorkerPool(cfg.MaxWorkers)
	client := &http.Client{Timeout: 10 * time.Second}
	
	processWorker := func(w Worker) error {
		return w.Process()
	}
	
	runServiceCheck(scanner, pool, client, processWorker)
}

func prepareScanner(filename string) (*bufio.Scanner, func(), error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("打开扫描结果文件失败: %v", err)
	}
	
	cleanup := func() {
		file.Close()
	}
	
	return bufio.NewScanner(file), cleanup, nil
}

func runServiceCheck(scanner *bufio.Scanner, pool *WorkerPool, client *http.Client, handler func(Worker) error) {
	pool.Start(handler)
	
	for scanner.Scan() {
		ip := strings.Split(scanner.Text(), ",")[0]
		pool.Submit(&ServiceCheckWorker{
			ip:     ip,
			port:   cfg.Port,
			client: client,
		})
	}
	
	pool.Wait()
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

	pool := NewWorkerPool(cfg.MaxWorkers)
	client := &http.Client{Timeout: timeout}

	pool.Start(func(w Worker) error {
		pool.Lock()
		defer pool.Unlock()
		return w.Process()
	})

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ",")
		if len(parts) != 2 {
			continue
		}

		pool.Submit(&BenchmarkWorker{
			ip:     parts[0],
			model:  parts[1],
			port:   cfg.Port,
			client: client,
			prompt: cfg.BenchPrompt,
			writer: writer,
		})
	}

	pool.Wait()

	ipModels := make(map[string][]string)
	benchResults := loadBenchResults()

	// 重新打开文件读取结果
	resultFile, err := os.Open(cfg.OutputFile)
	if err != nil {
		fmt.Printf("打开结果文件失败: %v\n", err)
		return
	}
	defer resultFile.Close()

	// 构建IP和模型的映射
	resultScanner := bufio.NewScanner(resultFile)
	for resultScanner.Scan() {
		parts := strings.Split(resultScanner.Text(), ",")
		if len(parts) != 2 {
			continue
		}
		
		ip := parts[0]
		model := parts[1]
		
		ipModels[ip] = append(ipModels[ip], model)
	}

	// 打印每个IP的结果
	for ip, models := range ipModels {
		printResult(ip, models, benchResults[ip])
	}

	if err := resultScanner.Err(); err != nil {
		fmt.Printf("扫描文件时出错: %v\n", err)
	}
}

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
