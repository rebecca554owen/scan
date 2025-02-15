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
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"github.com/spf13/viper"
)

// ScanResult 表示扫描结果
type ScanResult struct {
	IP     string
	Models []ModelInfo
}

// ModelInfo 表示模型信息
type ModelInfo struct {
	Name            string
	FirstTokenDelay time.Duration
	TokensPerSec    float64
	Status          string
}

// ProgressBar 表示进度条
type ProgressBar struct {
	total        int
	current      int
	width        int
	prefix       string
	startTime    time.Time
	mu           sync.Mutex
}

// Menu 表示菜单选项
type Menu struct {
	Title    string
	Handler  func() error
}

// 配置相关变量
var (
	port            int           // 服务器端口
	gatewayMAC      string        // 网关MAC地址
	inputFile       string        // 输入文件路径
	outputFile      string        // 输出文件路径
	timeout         time.Duration // 请求超时时间
	maxWorkers      int          // 最大工作线程数
	maxIdleConns    int          // 最大空闲连接数
	idleConnTimeout time.Duration // 空闲连接超时时间
	benchTimeout    time.Duration // 性能测试超时时间
	defaultCSVFile  string        // 默认CSV输出文件
	disableBench    bool          // 是否禁用性能测试
	benchPrompt     string        // 性能测试提示词
	portScanOnly    bool          // 是否仅扫描端口
	rate            int           // 扫描速率
	bandwidth       string        // 带宽限制
)

// 全局运行时变量
var (
	httpClient  *http.Client
	csvWriter   *csv.Writer
	csvFile     *os.File
	resultsChan chan ScanResult
	resultPool  = sync.Pool{
		New: func() interface{} {
			return &ScanResult{}
		},
	}
)

// init 初始化函数，程序启动时自动执行
func init() {
	// 配置文件初始化
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	
	// 设置默认值（选填参数）
	viper.SetDefault("maxWorkers", 200)
	viper.SetDefault("maxIdleConns", 100)
	viper.SetDefault("timeout", "3s")
	viper.SetDefault("idleConnTimeout", "90s")
	viper.SetDefault("benchTimeout", "30s")
	viper.SetDefault("disableBench", false)
	viper.SetDefault("benchPrompt", "用一句话自我介绍")
	viper.SetDefault("portScanOnly", false)
	viper.SetDefault("rate", 10000)
	viper.SetDefault("bandwidth", "10M")

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("⚠️ 读取配置文件失败: %v\n", err)
		os.Exit(1)
	}

	// 验证配置并加载
	if err := validateAndLoadConfig(); err != nil {
		fmt.Printf("⚠️ %v\n", err)
		os.Exit(1)
	}
	
	// 初始化HTTP客户端
	initHTTPClient()

	// 初始化结果通道
	resultsChan = make(chan ScanResult, maxWorkers*2)
}

// configureSettings 配置扫描参数
func configureSettings() error {
	fmt.Println("当前配置:")
	fmt.Printf("1. 扫描端口: %d\n", port)
	fmt.Printf("2. 网关MAC(可选): %s\n", gatewayMAC)
	fmt.Printf("3. 输入文件: %s\n", inputFile)
	fmt.Printf("4. 输出文件: %s\n", outputFile)
	fmt.Printf("5. 超时时间: %v\n", timeout)
	fmt.Printf("6. 并发数量: %d\n", maxWorkers)
	fmt.Printf("7. 性能测试: %v\n", !disableBench)
	fmt.Printf("8. 仅端口扫描: %v\n", portScanOnly)
	fmt.Printf("9. 扫描速率: %d/秒\n", rate)
	fmt.Printf("10. 带宽限制: %s\n", bandwidth)
	
	// 创建临时配置
	newConfig := make(map[string]interface{})
	
	fmt.Print("\n请选择要修改的配置项(1-10，回车返回): ")
	var choice int
	fmt.Scanf("%d\n", &choice)

	switch choice {
		case 1:
			fmt.Print("端口 (11434): ")
			var portStr string
			fmt.Scanf("%s\n", &portStr)
			if p, err := strconv.Atoi(portStr); err == nil {
				newConfig["port"] = p
			}
		case 2:
			fmt.Print("网关MAC: ")
			var mac string
			fmt.Scanf("%s\n", &mac)
			mac = formatMAC(mac)
			if mac != "" {
				newConfig["gatewayMAC"] = mac
			}
		case 3:
			fmt.Print("输入文件: ")
			var inputFileStr string
			fmt.Scanf("%s\n", &inputFileStr)
			if inputFileStr != "" {
				newConfig["inputFile"] = inputFileStr
			}
		case 4:
			fmt.Print("输出文件: ")
			var outputFileStr string
			fmt.Scanf("%s\n", &outputFileStr)
			if outputFileStr != "" {
				newConfig["outputFile"] = outputFileStr
			}
		case 5:
			fmt.Print("超时时间: ")
			var timeoutStr string
			fmt.Scanf("%s\n", &timeoutStr)
			if timeoutStr != "" {
				if t, err := time.ParseDuration(timeoutStr); err == nil {
					newConfig["timeout"] = t
				}
			}
		case 6:
			fmt.Print("并发数量: ")
			var maxWorkersStr string
			fmt.Scanf("%s\n", &maxWorkersStr)
			if maxWorkersStr != "" {
				if m, err := strconv.Atoi(maxWorkersStr); err == nil {
					newConfig["maxWorkers"] = m
				}
			}
		case 7:
			fmt.Print("性能测试: ")
			var disableBenchStr string
			fmt.Scanf("%s\n", &disableBenchStr)
			if disableBenchStr != "" {
				if b, err := strconv.ParseBool(disableBenchStr); err == nil {
					newConfig["disableBench"] = b
				}
			}
		case 8:
			fmt.Print("仅端口扫描: ")
			var portScanOnlyStr string
			fmt.Scanf("%s\n", &portScanOnlyStr)
			if portScanOnlyStr != "" {
				if p, err := strconv.ParseBool(portScanOnlyStr); err == nil {
					newConfig["portScanOnly"] = p
				}
			}
		case 9:
			fmt.Print("扫描速率 (10000): ")
			var rateStr string
			fmt.Scanf("%s\n", &rateStr)
			if r, err := strconv.Atoi(rateStr); err == nil {
				newConfig["rate"] = r
			}
		case 10:
			fmt.Print("带宽限制 (10M): ")
			var bw string
			fmt.Scanf("%s\n", &bw)
			if bw != "" {
				newConfig["bandwidth"] = bw
			}
		default:
			return nil
	}
	
	// 更新配置文件
	for k, v := range newConfig {
		viper.Set(k, v)
	}
	
	if err := viper.WriteConfig(); err != nil {
		return fmt.Errorf("保存配置失败: %v", err)
	}
	
	fmt.Println("✅ 配置已更新")
	return validateAndLoadConfig()
}

// validateAndLoadConfig 验证并加载配置
func validateAndLoadConfig() error {
	// 1. 先读取配置值
	port = viper.GetInt("port")
	gatewayMAC = viper.GetString("gatewayMAC")
	inputFile = viper.GetString("inputFile")
	outputFile = viper.GetString("outputFile")
	timeout = viper.GetDuration("timeout")
	
	// 2. 读取选填配置
	maxWorkers = viper.GetInt("maxWorkers")
	maxIdleConns = viper.GetInt("maxIdleConns")
	idleConnTimeout = viper.GetDuration("idleConnTimeout")
	benchTimeout = viper.GetDuration("benchTimeout")
	disableBench = viper.GetBool("disableBench")
	benchPrompt = viper.GetString("benchPrompt")
	portScanOnly = viper.GetBool("portScanOnly")
	rate = viper.GetInt("rate")
	bandwidth = viper.GetString("bandwidth")

	// 3. 验证必填参数
	requiredFields := []string{
		"port",
	}

	for _, field := range requiredFields {
		if !viper.IsSet(field) {
			return fmt.Errorf("缺少必填配置项: %s", field)
		}
	}

	// 4. 验证端口范围
	if port <= 0 || port > 65535 {
		return fmt.Errorf("端口号必须在1-65535之间，当前值: %d", port)
	}

	// 5. 验证MAC地址格式
	if gatewayMAC != "" {
		if _, err := net.ParseMAC(gatewayMAC); err != nil {
			return fmt.Errorf("无效的MAC地址格式: %v (正确格式示例：00:11:22:33:44:55)", err)
		}
		if !isValidGatewayMAC(gatewayMAC) {
			return fmt.Errorf("无法找到匹配的网关MAC地址，请使用arp -a命令确认或留空")
		}
	}

	// 6. 处理文件路径
	if inputFile == "" {
		inputFile = "ip.txt"  // 设置默认值
	}
	if outputFile == "" {
		outputFile = "results.csv"  // 设置默认值
	}

	// 7. 验证输入文件存在性
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		// 如果文件不存在，创建一个空文件
		f, err := os.Create(inputFile)
		if err != nil {
			return fmt.Errorf("无法创建输入文件: %v", err)
		}
		f.Close()
		fmt.Printf("已创建空的输入文件: %s\n", inputFile)
		fmt.Println("请在文件中添加要扫描的IP地址后重试")
		return fmt.Errorf("请先在输入文件中添加扫描目标")
	}

	// 验证速率参数
	if rate <= 0 {
		return fmt.Errorf("扫描速率必须大于0，当前值: %d", rate)
	}

	// 验证带宽格式（简单验证）
	if !strings.HasSuffix(bandwidth, "M") && !strings.HasSuffix(bandwidth, "K") {
		return fmt.Errorf("带宽格式不正确，示例：10M 或 100K")
	}

	return nil
}

// 新增网关MAC验证函数
func isValidGatewayMAC(mac string) bool {
	if mac == "" {
		return true // 允许为空
	}
	iface, err := net.InterfaceByName("eth0") // 根据实际情况调整网卡名称
	if err != nil {
		return false
	}
	
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		return false
	}
	
	// 获取网关IP（这里简化处理，实际可能需要更复杂的路由表解析）
	gatewayIP := strings.Split(addrs[0].String(), "/")[0]
	gatewayIP = strings.Join(strings.Split(gatewayIP, ".")[:3], ".") + ".1"
	
	// 执行arp命令获取真实网关MAC
	cmd := exec.Command("arp", "-n", gatewayIP)
	output, _ := cmd.Output()
	return strings.Contains(string(output), strings.ToLower(mac))
}

// initHTTPClient 初始化HTTP客户端
func initHTTPClient() {
    httpClient = &http.Client{
        Timeout: timeout,
        Transport: &http.Transport{
            MaxIdleConns: maxIdleConns,
            IdleConnTimeout: idleConnTimeout,
        },
    }
}

// main 程序入口函数
func main() {
	// 新增权限检查
	if os.Geteuid() != 0 {
		fmt.Println("请使用sudo权限运行本程序")
		os.Exit(1)
	}
	flag.Parse()
	
	// 显示帮助信息
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		printUsage()
		return
	}

	for {
		showMenu()
		choice := readMenuChoice()
		
		if choice == 0 {
			fmt.Println("\n👋 感谢使用，再见！")
			return
		}
		
		menus := getMenus()
		if choice > 0 && choice <= len(menus) {
			menu := menus[choice-1]
			fmt.Printf("\n=== %s ===\n", menu.Title)
			if err := menu.Handler(); err != nil {
				fmt.Printf("❌ 操作失败: %v\n", err)
			}
			fmt.Println("\n按回车键继续...")
			bufio.NewReader(os.Stdin).ReadString('\n')
		}
	}
}

// showMenu 显示主菜单
func showMenu() {
	fmt.Print("\033[H\033[2J") // 清屏
	fmt.Println("===========================================")
	fmt.Println("           端口扫描工具")
	fmt.Println("===========================================")
	
	menus := getMenus()
	for i, menu := range menus {
		fmt.Printf("%d. %s\n", i+1, menu.Title)
	}
	fmt.Println("0. 退出程序")
	fmt.Println("===========================================")
	fmt.Print("请选择操作 (0-4): ")
}

// readMenuChoice 读取用户输入的菜单选项
func readMenuChoice() int {
	var choice int
	fmt.Scanf("%d\n", &choice)
	return choice
}

// getMenus 获取菜单列表
func getMenus() []Menu {
	return []Menu{
		{"检查依赖", checkDependencies},
		{"配置参数", configureSettings},
		{"开始扫描", startScan},
		{"查看结果", viewResults},
	}
}

// checkDependencies 检查并安装依赖
func checkDependencies() error {
	fmt.Println("1. 检查 zmap...")
	if err := checkZmapInstalled(); err != nil {
		fmt.Printf("未检测到 zmap，是否立即安装？[y/N]: ")
		var answer string
		fmt.Scanf("%s\n", &answer)
		if strings.ToLower(answer) == "y" {
			cmd := exec.Command("sudo", "apt", "install", "zmap", "-y")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("安装 zmap 失败: %v", err)
			}
			fmt.Println("✅ zmap 安装成功")
		}
	} else {
		fmt.Println("✅ zmap 已安装")
	}
	
	fmt.Println("\n2. 检查配置文件...")
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}
	fmt.Println("✅ 配置文件正常")
	
	// 新增网络接口检查
	fmt.Println("\n3. 检查网络接口...")
	if iface := getActiveInterface(); iface != "" {
		fmt.Printf("✅ 使用网络接口: %s\n", iface)
	} else {
		return fmt.Errorf("未找到有效网络接口")
	}
	
	return nil
}

// getActiveInterface 获取活动网络接口
func getActiveInterface() string {
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			return iface.Name
		}
	}
	return ""
}

// startScan 开始扫描
func startScan() error {
	// 创建上下文用于控制程序退出
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 初始化CSV写入器
	initCSVWriter()
	defer csvFile.Close()

	// 设置信号处理
	setupSignalHandler(cancel)

	// 运行扫描流程
	return runScanProcess(ctx)
}

// viewResults 查看扫描结果
func viewResults() error {
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		return fmt.Errorf("结果文件不存在: %s", outputFile)
	}
	
	file, err := os.Open(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()
	
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}
	
	if len(records) <= 1 {
		return fmt.Errorf("暂无扫描结果")
	}
	
	fmt.Printf("共发现 %d 条记录:\n\n", len(records)-1)
	for i, record := range records {
		if i == 0 {
			fmt.Printf("%-15s | %-20s | %-10s", record[0], record[1], record[2])
			if len(record) > 3 {
				fmt.Printf(" | %-15s | %-10s", record[3], record[4])
			}
			fmt.Println("\n" + strings.Repeat("-", 80))
			continue
		}
		
		fmt.Printf("%-15s | %-20s | %-10s", record[0], record[1], record[2])
		if len(record) > 3 {
			fmt.Printf(" | %-15s | %-10s", record[3], record[4])
		}
		fmt.Println()
	}
	
	return nil
}

// printUsage 打印程序使用说明
func printUsage() {
	fmt.Println(`
使用说明:
--------
1. 环境依赖，确保已安装 zmap
2. 配置文件 config.yaml 
3. 准备包含目标IP的文件 ip.txt 
4. 运行程序开始扫描

配置文件示例:
-----------
port: 11434
gatewayMAC: "aa:bb:cc:dd:ee:ff"
inputFile: "ip.txt"
...
`)
}

// checkZmapInstalled 检查zmap是否已安装
func checkZmapInstalled() error {
	_, err := exec.LookPath("zmap")
	if err != nil {
		return fmt.Errorf("未检测到 zmap，请先安装: sudo apt install zmap")
	}
	
	cmd := exec.Command("zmap", "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("zmap 安装可能存在问题: %v", err)
	}
	
	return nil
}

// initCSVWriter 初始化CSV写入器
func initCSVWriter() {
	var err error
	csvFile, err = os.Create(outputFile)
	if err != nil {
		fmt.Printf("⚠️ 创建CSV文件失败: %v\n", err)
		return
	}

	csvWriter = csv.NewWriter(csvFile)
	headers := []string{"IP地址", "模型名称", "状态"}
	if !disableBench {
		headers = append(headers, "首Token延迟(ms)", "Tokens/s")
	}
	csvWriter.Write(headers)
}

// setupSignalHandler 设置信号处理函数
func setupSignalHandler(cancel context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
		fmt.Println("\n🛑 收到终止信号，正在清理资源...")
		if csvWriter != nil {
			csvWriter.Flush()
		}
		os.Exit(1)
	}()
}

// runScanProcess 运行扫描流程
func runScanProcess(ctx context.Context) error {
	fmt.Printf("🔍 开始扫描，使用网关: %s\n", gatewayMAC)
	
	// 第一阶段：端口扫描
	fmt.Println("\n第一阶段：端口扫描")
	if err := execZmap(); err != nil {
		return err
	}
	
	// 读取扫描结果获取IP总数
	ips, err := countIPs(outputFile)
	if err != nil {
		return err
	}
	
	// 确保IP总数大于0
	if ips <= 0 {
		return fmt.Errorf("未找到有效的IP地址，扫描结束")
	}

	// 第二阶段：Ollama服务检测
	if !portScanOnly {
		fmt.Println("\n第二阶段：Ollama服务检测")
		if err := processResults(ctx, ips); err != nil {
			return err
		}
	}
	
	return nil
}

// execZmap 执行zmap命令进行网络扫描
func execZmap() error {
	args := []string{
		"zmap",
		"-p", fmt.Sprintf("%d", port),
		"--rate", fmt.Sprintf("%d", rate),
		"-w", inputFile,
		"-o", outputFile,
		"-B", bandwidth,
	}

	if gatewayMAC != "" {
		args = append(args, "--gateway-mac", gatewayMAC)
	}

	cmd := exec.Command("sudo", args...)
	
	fmt.Printf("执行命令: %s\n", strings.Join(cmd.Args, " "))
	
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// countIPs 统计IP数量
func countIPs(file string) (int, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		if net.ParseIP(strings.TrimSpace(scanner.Text())) != nil {
			count++
		}
	}
	return count, scanner.Err()
}

// processResults 处理扫描结果
func processResults(ctx context.Context, totalIPs int) error {
	file, err := os.Open(outputFile)
	if err != nil {
		return fmt.Errorf("打开结果文件失败: %w", err)
	}
	defer file.Close()

	ips := make(chan string, maxWorkers*2)
	progressBar := NewProgressBar(totalIPs, "检测进度")

	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go worker(ctx, &wg, ips, progressBar)
	}

	go resultHandler()

	go func() {
		defer close(ips)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if net.ParseIP(ip) != nil {
				ips <- ip
			}
		}
	}()

	wg.Wait()
	close(resultsChan)

	csvWriter.Flush()
	fmt.Printf("\n✅ 结果已保存至 %s\n", outputFile)
	return nil
}

// resultHandler 处理扫描结果，将结果打印并写入CSV
func resultHandler() {
	for res := range resultsChan {
		printResult(res)
		writeCSV(res)
	}
}

// printResult 格式化打印扫描结果
func printResult(res ScanResult) {
	fmt.Printf("\nIP地址: %s\n", res.IP)
	fmt.Println(strings.Repeat("-", 50))
	for _, model := range res.Models {
		fmt.Printf("├─ 模型: %-25s\n", model.Name)
		if !disableBench {
			fmt.Printf("│  ├─ 状态: %s\n", model.Status)
			fmt.Printf("│  ├─ 首Token延迟: %v\n", model.FirstTokenDelay.Round(time.Millisecond))
			fmt.Printf("│  └─ 生成速度: %.1f tokens/s\n", model.TokensPerSec)
		} else {
			fmt.Printf("│  └─ 状态: %s\n", model.Status)
		}
		fmt.Println(strings.Repeat("-", 50))
	}
}

// writeCSV 将扫描结果写入CSV文件
func writeCSV(res ScanResult) {
	for _, model := range res.Models {
		record := []string{res.IP, model.Name, model.Status}
		if !disableBench {
			record = append(record,
				fmt.Sprintf("%.0f", model.FirstTokenDelay.Seconds()*1000),
				fmt.Sprintf("%.1f", model.TokensPerSec),
			)
		}
		csvWriter.Write(record)
	}
}

// worker 工作线程，处理每个IP的扫描任务
func worker(ctx context.Context, wg *sync.WaitGroup, ips <-chan string, progressBar *ProgressBar) {
	defer wg.Done()
	
	batch := make([]string, 0, 10)
	for ip := range ips {
		batch = append(batch, ip)
		if len(batch) == 10 {
			processBatch(ctx, batch)
			for range batch {
				progressBar.Increment()
			}
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		processBatch(ctx, batch)
		for range batch {
			progressBar.Increment()
		}
	}
}

// processBatch 处理一批IP的扫描任务
func processBatch(ctx context.Context, ips []string) {
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return
		default:
			if checkPort(ip) {
				result := resultPool.Get().(*ScanResult)
				result.IP = ip
				
				if portScanOnly {
					// 仅端口扫描模式
					info := ModelInfo{
						Name:   "PORT_SCAN",
						Status: "开放",
					}
					result.Models = append(result.Models, info)
					resultsChan <- *result
				} else if checkOllama(ip) {
					// Ollama 服务扫描模式
					if models := getModels(ip); len(models) > 0 {
						models = sortModels(models)
						for _, model := range models {
							info := ModelInfo{Name: model}
							if !disableBench {
								latency, tps, status := benchmarkModel(ip, model)
								info.FirstTokenDelay = latency
								info.TokensPerSec = tps
								info.Status = status
							} else {
								info.Status = "发现"
							}
							result.Models = append(result.Models, info)
						}
						resultsChan <- *result
					}
				}
				resultPool.Put(result)
			}
		}
	}
}

// checkPort 检查目标IP的指定端口是否开放
func checkPort(ip string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// checkOllama 检查目标IP是否运行Ollama服务
func checkOllama(ip string) bool {
	resp, err := httpClient.Get(fmt.Sprintf("http://%s:%d", ip, port))
	if err != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	defer resp.Body.Close()

	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	return strings.Contains(string(buf[:n]), "Ollama is running")
}

// getModels 从目标IP获取模型列表
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

// parseModelSize 从模型名称中解析模型大小
func parseModelSize(model string) float64 {
	parts := strings.Split(model, ":")
	if len(parts) < 2 {
		return 0
	}

	sizeStr := strings.TrimSuffix(parts[len(parts)-1], "b")
	size, err := strconv.ParseFloat(sizeStr, 64)
	if err != nil {
		return 0
	}
	return size
}

// sortModels 按模型大小对模型列表进行排序
func sortModels(models []string) []string {
	sort.Slice(models, func(i, j int) bool {
		return parseModelSize(models[i]) < parseModelSize(models[j])
	})
	return models
}

// benchmarkModel 对指定模型进行性能测试
func benchmarkModel(ip, model string) (time.Duration, float64, string) {
	if disableBench {
		return 0, 0, "未测试"
	}

	start := time.Now()
	
	payload := map[string]interface{}{
		"model":  model,
		"prompt": benchPrompt,
		"stream": true,
	}

	body, _ := json.Marshal(payload)
	
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("http://%s:%d/api/generate", ip, port),
		bytes.NewReader(body))

	client := &http.Client{Timeout: benchTimeout}
	
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

// NewProgressBar 创建新的进度条实例
func NewProgressBar(total int, prefix string) *ProgressBar {
	return &ProgressBar{
		total:     total,
		width:     50,
		prefix:    prefix,
		startTime: time.Now(),
	}
}

func (p *ProgressBar) Increment() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current++
	p.display()
}

func (p *ProgressBar) display() {
	percentage := float64(p.current) * 100 / float64(p.total)
	filled := int(float64(p.width) * float64(p.current) / float64(p.total))
	
	// 计算预计剩余时间
	elapsed := time.Since(p.startTime)
	var eta time.Duration
	if p.current > 0 {
		eta = time.Duration(float64(elapsed) * float64(p.total-p.current) / float64(p.current))
	}
	
	// 使用颜色和清除行的转义序列
	bar := strings.Repeat("█", filled) + strings.Repeat("░", p.width-filled)
	fmt.Printf("\r\033[K%s [%s] %.1f%% (%d/%d) ETA: %v", 
		p.prefix, bar, percentage, p.current, p.total, eta.Round(time.Second))
	
	if p.current >= p.total {
		fmt.Println()
	}
}

// 新增MAC地址格式化函数
func formatMAC(input string) string {
	input = strings.ReplaceAll(input, "-", ":")
	parts := strings.Split(input, ":")
	if len(parts) != 6 {
		return ""
	}
	return fmt.Sprintf("%02s:%02s:%02s:%02s:%02s:%02s",
		parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])
}
