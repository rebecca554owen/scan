package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
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

// ScanResult 扫描结果结构体
type ScanResult struct {
	IP     string
	Models []ModelInfo
}

// ModelInfo 模型信息结构体
type ModelInfo struct {
	Name           string
	Status         string
	FirstTokenDelay time.Duration
	TokensPerSec    float64
}

// Config 配置结构体
type Config struct {
	// 扫描参数
	Port       int    `mapstructure:"port"`
	InputFile  string `mapstructure:"inputFile"`
	OutputFile string `mapstructure:"outputFile"`
	Bandwidth  string `mapstructure:"bandwidth"`
	Rate       int    `mapstructure:"rate"`

	// HTTP配置
	Timeout         time.Duration `mapstructure:"timeout"`
	IdleConnTimeout time.Duration `mapstructure:"idleConnTimeout"`
	MaxWorkers      int          `mapstructure:"maxWorkers"`
	MaxIdleConns    int          `mapstructure:"maxIdleConns"`

	// 性能测试
	DisableBench    bool          `mapstructure:"disableBench"`
	BenchPrompt     string        `mapstructure:"benchPrompt"`
	BenchTimeout    time.Duration `mapstructure:"benchTimeout"`
}

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

	// 添加计数器跟踪有效结果
	validServices int64
	mu           sync.Mutex

	// 添加 semaphore 定义
	semaphore = make(chan struct{}, runtime.NumCPU()*2)
)

// WorkerPool 工作协程池结构体
type WorkerPool struct {
	workers chan struct{}  // 工作任务通道
	wg      sync.WaitGroup // 等待组
}

// NewWorkerPool 创建新的工作协程池
// size: 池的大小（最大并发数）
func NewWorkerPool(size int) *WorkerPool {
	return &WorkerPool{
		workers: make(chan struct{}, size),
	}
}

// Submit 提交任务到工作协程池
// ctx: 上下文，用于任务取消
// task: 要执行的任务函数
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

// showMenu 显示主菜单
func showMenu() {
	fmt.Println("\n======== Ollama 扫描工具 ========")
	fmt.Println("1. 检查并安装依赖")
	fmt.Println("2. 配置扫描参数")
	fmt.Println("3. 启动端口扫描")
	fmt.Println("4. 检测 Ollama 服务")
	fmt.Println("5. 性能测试")
	fmt.Println("6. 一键执行全部流程")
	fmt.Println("7. 查看扫描结果")
	fmt.Println("8. 清空数据")
	fmt.Println("0. 退出程序")
	fmt.Print("\n请选择操作 (0-8): ")
}

// main 程序入口
func main() {
	for {
		showMenu()
		
		var choice int
		fmt.Scanln(&choice)
		
		switch choice {
		case 0:
			fmt.Println("👋 感谢使用，再见！")
			return
			
		case 1:
			fmt.Println("\n=== 依赖检查 ===")
			if err := checkDependencies(); err != nil {
				fmt.Printf("❌ 依赖检查失败: %v\n", err)
			} else {
				fmt.Println("✅ 依赖检查完成")
			}
			
		case 2:
			configScanParams()
			
		case 3:
			startPortScan()
			
		case 4:
			detectOllamaService()
			
		case 5:
			runPerformanceTest()
			
		case 6:
			runFullProcess()
			
		case 7:
			viewScanResults()
			
		case 8:
			clearData()
			
		default:
			fmt.Println("❌ 无效的选项，请重新选择")
		}
		
		// 暂停一下，让用户看清结果
		fmt.Print("\n按回车键继续...")
		fmt.Scanln()
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

// loadAndValidateConfig 加载和验证配置
func loadAndValidateConfig() (*Config, error) {
	// 设置默认值
	setDefaultConfig()
	
	// 读取配置文件
	var cfg Config
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("读取配置文件失败: %v", err)
		}
	}
	
	// 解析到结构体
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %v", err)
	}
	
	// 验证配置
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	
	return &cfg, nil
}

func setDefaultConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	// 扫描参数默认值
	viper.SetDefault("port", 11434)
	viper.SetDefault("inputFile", "ip.txt")
	viper.SetDefault("outputFile", "results.csv")
	viper.SetDefault("rate", 10000)
	viper.SetDefault("bandwidth", "100M")

	// HTTP配置参数默认值
	viper.SetDefault("timeout", "3s")
	viper.SetDefault("idleConnTimeout", "90s")
	viper.SetDefault("maxWorkers", runtime.NumCPU()*20)
	viper.SetDefault("maxIdleConns", runtime.NumCPU()*10)

	// 性能测试参数默认值
	viper.SetDefault("disableBench", false)
	viper.SetDefault("benchPrompt", "用一句话自我介绍")
	viper.SetDefault("benchTimeout", "30s")
}

func validateConfig(cfg *Config) error {
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return fmt.Errorf("无效的端口号: %d", cfg.Port)
	}
	if cfg.MaxWorkers <= 0 {
		return fmt.Errorf("无效的工作线程数: %d", cfg.MaxWorkers)
	}
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

// execZmap 执行Zmap扫描
func execZmap(cfg *Config) error {
	args := []string{
		"zmap",
		"-p", fmt.Sprintf("%d", cfg.Port),
		"-w", cfg.InputFile,
		"-o", cfg.OutputFile,
		"-B", cfg.Bandwidth,
		"--rate", fmt.Sprintf("%d", cfg.Rate),
	}

	fmt.Printf("执行命令: %s\n", strings.Join(args, " "))
	
	cmd := exec.Command(args[0], args[1:]...)
	
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// initCSVWriter 初始化CSV写入器
func initCSVWriter() error {
	var err error
	csvFile, err = os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("创建CSV文件失败: %v", err)
	}

	csvWriter = csv.NewWriter(csvFile)
	headers := []string{"IP地址", "端口", "模型名称", "状态"}
	if !disableBench {
		headers = append(headers, "首个token延迟(ms)", "每秒token数")
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
		fmt.Println("\n🛑 收到终止信号，清理资源...")
		if csvWriter != nil {
			csvWriter.Flush()
		}
		os.Exit(1)
	}()
}

// processResults 处理扫描结果
func processResults(ctx context.Context) error {
	// 等待zmap输出文件写入完成
	time.Sleep(1 * time.Second)
	
	file, err := os.Open(outputFile)
	if err != nil {
		return fmt.Errorf("打开结果文件失败: %w", err)
	}
	defer file.Close()

	pool := NewWorkerPool(maxWorkers)
	
	go resultHandler()

	var processedCount int
	var totalCount int
	
	// 先统计总行数
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if net.ParseIP(strings.TrimSpace(scanner.Text())) != nil {
			totalCount++
		}
	}
	
	file.Seek(0, 0) // 重置文件指针
	scanner = bufio.NewScanner(file)
	
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if net.ParseIP(ip) != nil {
			processedCount++
			fmt.Printf("\rProcessing IP %d/%d (%d%%)", processedCount, totalCount, processedCount*100/totalCount)
			
			pool.Submit(ctx, func() {
				processIP(ctx, ip)
			})
		}
	}

	pool.Wait()
	close(resultsChan)
	
	csvWriter.Flush()
	fmt.Printf("\n✅ 结果已保存至 %s\n", outputFile)
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
		fmt.Printf("├─ 模型: %-25s\n", model.Name)
		if !disableBench {
			fmt.Printf("│  ├─ 状态: %s\n", model.Status)
			fmt.Printf("│  ├─ 首个token延迟: %v\n", model.FirstTokenDelay.Round(time.Millisecond))
			fmt.Printf("│  └─ 每秒token数: %.1f\n", model.TokensPerSec)
		} else {
			fmt.Printf("│  └─ 状态: %s\n", model.Status)
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
// 返回：首个 token 延迟、每秒token数、状态信息
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
		return 0, 0, "连接失败"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Sprintf("HTTP状态码 %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var (
		首个令牌时间 time.Time
		最后令牌时间 time.Time
		令牌计数    int
	)

	for scanner.Scan() {
		if 令牌计数 == 0 {
			首个令牌时间 = time.Now()
		}
		最后令牌时间 = time.Now()
		令牌计数++

		var data map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &data); err != nil {
			continue
		}

		if done, _ := data["done"].(bool); done {
			break
		}
	}

	if 令牌计数 == 0 {
		return 0, 0, "无响应"
	}

	首个token延迟 := 首个令牌时间.Sub(time.Now())
	总用时 := 最后令牌时间.Sub(首个令牌时间)
	每秒token数 := float64(令牌计数) / 总用时.Seconds()

	return 首个token延迟, 每秒token数, "成功"
}

// processIP 处理单个IP的扫描任务
func processIP(ctx context.Context, ip string) {
	// 添加超时控制:
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	// 添加并发限制:
	select {
	case <-ctx.Done():
		return
	case semaphore <- struct{}{}:
		defer func() { <-semaphore }()
	}

	if !checkPort(ip) {
		return
	}

	if !checkOllama(ip) {
		return
	}

	models := getModels(ip)
	if len(models) == 0 {
		return
	}

	models = sortModels(models)
	result := resultPool.Get().(*ScanResult)
	result.IP = ip
	
	for _, model := range models {
		var modelInfo ModelInfo
		modelInfo.Name = model
		
		if !disableBench {
			firstTokenDelay, tokensPerSec, status := benchmarkModel(ip, model)
			modelInfo.FirstTokenDelay = firstTokenDelay
			modelInfo.TokensPerSec = tokensPerSec
			modelInfo.Status = status
		} else {
			modelInfo.Status = "Available"
		}
		
		result.Models = append(result.Models, modelInfo)
	}

	select {
	case resultsChan <- *result:
	case <-ctx.Done():
		return
	}

	// 重置并归还对象到对象池
	result.IP = ""
	result.Models = result.Models[:0]
	resultPool.Put(result)
}

func configScanParams() {
	cfg, err := loadAndValidateConfig()
	if err != nil {
		fmt.Printf("❌ 加载配置失败: %v\n", err)
		return
	}
	
	fmt.Printf("\n当前配置:\n")
	fmt.Printf("  扫描端口: %d\n", cfg.Port)
	fmt.Printf("  输入文件: %s\n", cfg.InputFile)
	fmt.Printf("  输出文件: %s\n", cfg.OutputFile)
	fmt.Printf("  扫描速率: %d\n", cfg.Rate)
	fmt.Printf("  带宽限制: %s\n", cfg.Bandwidth)
	
	fmt.Print("\n是否修改配置? (y/n): ")
	var choice string
	fmt.Scanln(&choice)
	if strings.ToLower(choice) != "y" {
		return
	}
	
	fmt.Printf("请输入扫描端口 (当前: %d): ", cfg.Port)
	var input string
	fmt.Scanln(&input)
	if input != "" {
		if p, err := strconv.Atoi(input); err == nil && p > 0 && p < 65536 {
			viper.Set("port", p)
		}
	}
	
	// 类似地实现其他参数的修改...
	
	if err := viper.WriteConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			err = viper.SafeWriteConfig()
		}
		if err != nil {
			fmt.Printf("❌ 保存配置失败: %v\n", err)
			return
		}
	}
	
	fmt.Println("✅ 配置已更新")
}

func startPortScan() {
	fmt.Println("\n=== 端口扫描 ===")
	
	cfg, err := loadAndValidateConfig()
	if err != nil {
		fmt.Printf("❌ 配置加载失败: %v\n", err)
		return
	}
	
	// 让用户确认或修改端口
	fmt.Printf("当前扫描端口: %d\n", cfg.Port)
	fmt.Print("请输入要扫描的端口 (直接回车使用当前配置): ")
	var input string
	fmt.Scanln(&input)
	if input != "" {
		if p, err := strconv.Atoi(input); err == nil && p > 0 && p < 65536 {
			port = p
		} else {
			fmt.Printf("❌ 无效的端口号，将使用配置文件中的端口: %d\n", cfg.Port)
			port = cfg.Port
		}
	} else {
		port = cfg.Port
	}
	
	if err := execZmap(cfg); err != nil {
		fmt.Printf("❌ 端口扫描失败: %v\n", err)
		return
	}
	
	// 显示扫描结果
	showScanResults()
}

func detectOllamaService() {
	fmt.Println("\n=== Ollama 服务检测 ===")
	
	cfg, err := loadAndValidateConfig()
	if err != nil {
		fmt.Printf("❌ 配置加载失败: %v\n", err)
		return
	}
	
	// 使用配置参数
	outputFile = cfg.OutputFile
	maxWorkers = cfg.MaxWorkers
	timeout = cfg.Timeout
	idleConnTimeout = cfg.IdleConnTimeout

	// 初始化HTTP客户端
	initHTTPClient()
	
	// 打开扫描结果文件
	file, err := os.Open(outputFile)
	if err != nil {
		fmt.Printf("❌ 打开扫描结果文件失败: %v\n", err)
		return
	}
	defer file.Close()
	
	// 初始化CSV写入器
	if err := initCSVWriter(); err != nil {
		fmt.Printf("❌ CSV文件初始化失败: %v\n", err)
		return
	}
	
	// 创建上下文和取消函数
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// 设置信号处理
	setupSignalHandler(cancel)
	
	// 初始化结果通道和对象池
	resultsChan = make(chan ScanResult, maxWorkers)
	resultPool = sync.Pool{
		New: func() interface{} {
			return &ScanResult{}
		},
	}
	
	// 启动结果处理协程
	go resultHandler()
	
	// 创建工作池
	pool := NewWorkerPool(maxWorkers)
	
	// 扫描文件中的IP
	scanner := bufio.NewScanner(file)
	var totalIPs int
	var validIPs int
	
	fmt.Println("正在检测IP地址是否运行Ollama服务...")
	
	// 先统计总IP数
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if net.ParseIP(ip) != nil {
			totalIPs++
		}
	}
	
	// 重置文件指针
	file.Seek(0, 0)
	scanner = bufio.NewScanner(file)
	
	// 处理每个IP
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if net.ParseIP(ip) != nil {
			validIPs++
			fmt.Printf("\r检测进度: %d/%d (%d%%)", validIPs, totalIPs, validIPs*100/totalIPs)
			
			pool.Submit(ctx, func() {
				// 检查端口是否开放
				if !checkPort(ip) {
					return
				}
				
				// 检查是否运行Ollama服务
				if !checkOllama(ip) {
					return
				}
				
				// 获取模型列表
				models := getModels(ip)
				if len(models) == 0 {
					return
				}
				
				// 对模型排序
				models = sortModels(models)
				
				// 从对象池获取结果对象
				result := resultPool.Get().(*ScanResult)
				result.IP = ip
				
				// 处理每个模型
				for _, model := range models {
					var modelInfo ModelInfo
					modelInfo.Name = model
					
					if !disableBench {
						// 执行性能测试
						firstTokenDelay, tokensPerSec, status := benchmarkModel(ip, model)
						modelInfo.FirstTokenDelay = firstTokenDelay
						modelInfo.TokensPerSec = tokensPerSec
						modelInfo.Status = status
					} else {
						modelInfo.Status = "可用"
					}
					
					result.Models = append(result.Models, modelInfo)
				}
				
				// 将结果发送到通道
				select {
				case resultsChan <- *result:
				case <-ctx.Done():
					return
				}
				
				// 重置并归还对象到对象池
				result.IP = ""
				result.Models = result.Models[:0]
				resultPool.Put(result)
			})
		}
	}
	
	// 等待所有任务完成
	pool.Wait()
	
	// 关闭结果通道
	close(resultsChan)
	
	// 刷新CSV写入器
	csvWriter.Flush()
	
	// 打印完成信息
	fmt.Printf("\n\n✅ Ollama服务检测完成，发现 %d 个可用服务\n", validServices)
	fmt.Printf("详细结果已保存至: %s\n", outputFile)

	defer func() {
		if csvWriter != nil {
			csvWriter.Flush()
		}
		if csvFile != nil {
			csvFile.Close()
		}
	}()
}

func runPerformanceTest() {
	fmt.Println("\n=== Ollama 性能测试 ===")
	
	if disableBench {
		fmt.Print("性能测试当前已禁用，是否启用? (y/n): ")
		var choice string
		fmt.Scanln(&choice)
		if strings.ToLower(choice) == "y" {
			disableBench = false
			viper.Set("disableBench", false)
			viper.WriteConfig()
		} else {
			fmt.Println("❌ 性能测试已取消")
			return
		}
	}
	
	// 提示用户输入或确认测试提示词
	fmt.Printf("当前测试提示词: %s\n", benchPrompt)
	fmt.Print("请输入新的测试提示词 (直接回车使用当前配置): ")
	var input string
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		input = scanner.Text()
		if input != "" {
			benchPrompt = input
			viper.Set("benchPrompt", input)
			viper.WriteConfig()
		}
	}
	
	detectOllamaService()
}

func runFullProcess() {
	fmt.Println("\n=== 一键执行全部流程 ===")
	
	// 1. 检查依赖
	fmt.Println("\n>> 第一步: 检查依赖")
	if err := checkDependencies(); err != nil {
		fmt.Printf("❌ 依赖检查失败: %v\n", err)
		return
	}
	
	// 2. 配置扫描参数 - 使用默认配置
	cfg, err := loadAndValidateConfig()
	if err != nil {
		fmt.Printf("❌ 配置加载失败: %v\n", err)
		return
	}
	
	// 3. 启动端口扫描
	fmt.Println("\n>> 第二步: 启动端口扫描")
	if err := execZmap(cfg); err != nil {
		fmt.Printf("❌ 端口扫描失败: %v\n", err)
		return
	}
	showScanResults()
	
	// 4. 检测Ollama服务
	fmt.Println("\n>> 第三步: 检测Ollama服务")
	detectOllamaService()
	
	// 5. 如果启用了性能测试，则执行
	if !disableBench {
		fmt.Println("\n>> 第四步: 执行性能测试")
		runPerformanceTest()
	}
	
	fmt.Println("\n✅ 全部流程执行完毕!")
}

func viewScanResults() {
	fmt.Println("\n=== 查看扫描结果 ===")
	
	// 1. 查看端口扫描结果
	fmt.Println("\n>> 端口扫描结果:")
	showScanResults()
	
	// 2. 查看服务检测结果
	fmt.Println("\n>> Ollama服务检测结果:")
	file, err := os.Open(outputFile)
	if err != nil {
		handleError(err, "无法打开结果文件")
		return
	}
	defer file.Close()
	
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Printf("❌ 读取CSV文件失败: %v\n", err)
		return
	}
	
	if len(records) <= 1 {
		fmt.Println("暂无服务检测结果")
		return
	}
	
	// 打印表头
	fmt.Println(strings.Join(records[0], "\t"))
	fmt.Println(strings.Repeat("-", 80))
	
	// 打印数据行
	for _, record := range records[1:] {
		fmt.Println(strings.Join(record, "\t"))
	}
}

func clearData() {
	fmt.Println("\n=== 清空数据 ===")
	fmt.Println("1. 清空输入文件")
	fmt.Println("2. 清空输出文件")
	fmt.Println("3. 清空所有数据")
	fmt.Println("0. 返回主菜单")
	fmt.Print("\n请选择操作 (0-3): ")
	
	var choice int
	fmt.Scanln(&choice)
	
	cfg, err := loadAndValidateConfig()
	if err != nil {
		fmt.Printf("❌ 配置加载失败: %v\n", err)
		return
	}

	var operations = map[int]struct {
		name   string
		action func(*Config) error
	}{
		1: {"清空输入文件", func(cfg *Config) error { 
			return os.WriteFile(cfg.InputFile, []byte{}, 0644) 
		}},
		2: {"清空输出文件", func(cfg *Config) error { 
			return os.WriteFile(cfg.OutputFile, []byte{}, 0644) 
		}},
		3: {"清空所有数据", func(cfg *Config) error {
			if err := os.WriteFile(cfg.InputFile, []byte{}, 0644); err != nil {
				return err
			}
			return os.WriteFile(cfg.OutputFile, []byte{}, 0644)
		}},
	}

	if op, exists := operations[choice]; exists {
		if err := op.action(cfg); err != nil {
			fmt.Printf("❌ %s失败: %v\n", op.name, err)
		} else {
			fmt.Printf("✅ %s已清空\n", op.name)
		}
	} else if choice != 0 {
		fmt.Println("❌ 无效的选项")
	}
}

// showScanResults 显示端口扫描结果
func showScanResults() {
	if file, err := os.Open(outputFile); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		fmt.Println("\n发现开放端口的IP地址：")
		count := 0
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if net.ParseIP(ip) != nil {
				fmt.Printf("  %s:%d\n", ip, port)
				count++
			}
		}
		if count == 0 {
			fmt.Println("  未发现开放端口的IP地址")
		}
		fmt.Printf("\n总计: %d 个IP地址\n", count)
	} else {
		fmt.Printf("❌ 无法打开结果文件: %v\n", err)
	}
}

func handleError(err error, message string) {
	if err != nil {
		fmt.Printf("❌ %s: %v\n", message, err)
		return
	}
}
