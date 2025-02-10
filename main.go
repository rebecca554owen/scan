package main

import (
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"sync/atomic"

	"github.com/spf13/viper"
)

// 全局变量
var cfg *Config             // config.yaml结构体
var csvWriter *csv.Writer   // result.csv结构体
var csvMutex sync.Mutex     // 用于csv文件的并发写入

// config.yaml 结构体
type Config struct {
    Port         int           `yaml:"port"`
    Rate         int           `yaml:"rate"`
    Bandwidth    string        `yaml:"bandwidth"`
    InputFile    string        `yaml:"inputFile"`
    OutputFile   string        `yaml:"outputFile"`
    MaxWorkers   int           `yaml:"maxWorkers"`
    Timeout      time.Duration `yaml:"timeout"`
    BenchPrompt  string        `yaml:"benchPrompt"`
    BenchTimeout time.Duration `yaml:"benchTimeout"`
}

// result.csv 结构体
type ScanResult struct {
    IP             string         // IP地址
    ModelNames     []string       // 模型名称列表
    Status         string         // 服务状态
    FirstTokenDelay time.Duration // 首个token生成延迟
    TokensPerSec    float64       // 每秒生成token数
}

// progressBar 进度条结构体
type progressBar struct {
    current int
    total   int
    width   int
}

// newProgressBar 创建新的进度条
func newProgressBar(total int) *progressBar {
    return &progressBar{
        current: 0,
        total:   total,
        width:   50,
    }
}

// update 更新进度条
func (p *progressBar) update(current int) {
    p.current = current
    p.render()
}

// render 渲染进度条
func (p *progressBar) render() {
    percentage := float64(p.current) / float64(p.total)
    filled := int(float64(p.width) * percentage)
    
    // 清除当前行
    fmt.Printf("\r")
    
    // 进度条
    fmt.Printf("[")
    for i := 0; i < p.width; i++ {
        if i < filled {
            fmt.Printf("=")
        } else {
            fmt.Printf(" ")
        }
    }
    
    // 百分比
    fmt.Printf("] %3.0f%% (%d/%d)", percentage*100, p.current, p.total)
}

// done 完成进度条
func (p *progressBar) done() {
    fmt.Println()
}

// main 主函数
func main() {
    // 创建上下文用于控制程序退出
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    // 加载并验证配置
    if err := loadConfig(); err != nil {
        fmt.Printf("加载配置失败: %v\n", err)
        os.Exit(1)
    }
    
    // 显示菜单,传入上下文
    showMenu(ctx)
}

// showMenu 系统菜单
func showMenu(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        default:
            fmt.Println("\n请选择要执行的操作：")
            fmt.Println("1. 检查依赖")
            fmt.Println("2. 端口扫描")
            fmt.Println("3. 检测服务")
            fmt.Println("4. 性能测试")
            fmt.Println("0. 退出")
            fmt.Print("请输入选项：")
            
            var choice int   
            fmt.Scanln(&choice)
            
            switch choice {
            case 1:
                checkZmap(ctx)
            case 2:
                runZmapScan(ctx, cfg)
            case 3:
                checkOllamaService(ctx)
            case 4:
                benchmarkModel(ctx)
            case 0:
                fmt.Println("退出程序")
                return
            default:
                fmt.Println("无效选项，请重新选择")
            }
        }
    }
}

// 菜单1,主要检查zmap依赖，如果未安装则安装，加载并验证配置，提供一些默认值

// checkZmap 检查zmap依赖
func checkZmap(ctx context.Context) {
    if _, err := exec.LookPath("zmap"); err != nil {
        fmt.Println("zmap未安装，开始安装...")
        cmd := exec.Command("sudo", "apt-get", "install", "zmap", "-y")
        if err := cmd.Run(); err != nil {
            fmt.Printf("安装zmap失败: %v\n", err)
            return
        }
        fmt.Println("zmap安装完成")
    } else {    
        fmt.Println("zmap已安装")
    }
}

// loadConfig 加载配置
func loadConfig() error {
    // 设置默认值必须在读取配置前
    viper.SetDefault("port", 11434)
    viper.SetDefault("inputFile", "ip.txt")
    viper.SetDefault("outputFile", "results.csv")
    viper.SetDefault("timeout", "5s")
    viper.SetDefault("maxWorkers", 100)
    viper.SetDefault("benchPrompt", "用一句话自我介绍")
    viper.SetDefault("benchTimeout", "30s")

    // 读取配置
    viper.SetConfigName("config")
    viper.AddConfigPath(".")
    if err := viper.ReadInConfig(); err != nil {
        return fmt.Errorf("读取配置文件失败: %w", err)
    }

    // 解析动态参数
    timeout, err := time.ParseDuration(viper.GetString("timeout"))
    if err != nil {
        return fmt.Errorf("解析超时时间失败: %w", err)
    }
    
    benchTimeout, err := time.ParseDuration(viper.GetString("benchTimeout"))
    if err != nil {
        return fmt.Errorf("解析性能测试超时失败: %w", err)
    }

    // 创建配置对象
    cfg = &Config{
        Port:        viper.GetInt("port"),
        InputFile:   viper.GetString("inputFile"),
        OutputFile:  viper.GetString("outputFile"),
        Bandwidth:   viper.GetString("bandwidth"),
        Rate:        viper.GetInt("rate"),
        Timeout:     timeout,
        MaxWorkers:  viper.GetInt("maxWorkers"),
        BenchPrompt: viper.GetString("benchPrompt"),
        BenchTimeout: benchTimeout,
    }

    // 最后执行完整验证
    if err := validateConfig(cfg); err != nil {
        return fmt.Errorf("配置验证失败: %w", err)
    }
    
    return nil
}

func validateConfig(cfg *Config) error {
    // 验证解析后的数值型参数
    if cfg.Timeout <= 0 {
        return fmt.Errorf("超时时间必须大于0")
    }
    if cfg.BenchTimeout <= 0 {
        return fmt.Errorf("性能测试超时必须大于0")
    }
    
    // 验证带宽格式
    if !strings.HasSuffix(cfg.Bandwidth, "M") && !strings.HasSuffix(cfg.Bandwidth, "K") {
        return fmt.Errorf("带宽格式错误，必须为数字+K/M")
    }
    
    // 验证文件存在性
    if _, err := os.Stat(cfg.InputFile); os.IsNotExist(err) {
        return fmt.Errorf("输入文件不存在: %s", cfg.InputFile)
    }
    
    return nil
}

// 菜单2相关函数，主要是扫描并输出结果到ip.csv

// runZmapScan 执行zmap扫描到ip.csv
func runZmapScan(ctx context.Context, cfg *Config) error {
    // 构建zmap命令
    args := []string{
        "zmap",
        "-w", cfg.InputFile,
        "-p", strconv.Itoa(cfg.Port),
        "-r", strconv.Itoa(cfg.Rate),
        "-B", cfg.Bandwidth,
        "-o", "ip.csv",
    }
    
    // 创建命令对象
    cmd := exec.Command("sudo", args...)
    
    // 打印完整命令
    fmt.Printf("执行命令: zmap %s\n", strings.Join(args, " "))
    
    // 将命令的标准输出和错误输出重定向到终端
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    
    // 执行命令
    err := cmd.Run()
    if err != nil {
        fmt.Printf("执行zmap失败: %v\n", err)
        return err
    }
    
    fmt.Println("zmap扫描完成")
    return nil
}

// 菜单3相关函数，初始化HTTP客户端，CSV文件，先检查ip.csv中的ip端口是否开放，再检查是否为Ollama服务，获取模型列表并排序

// readFileLines 读取文件行
func readFileLines(filename string) ([]string, error) {
    content, err := os.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    return strings.Split(strings.TrimSpace(string(content)), "\n"), nil
}

// 如果端口开放就检查Ollama服务
func checkOllamaService(ctx context.Context) {
    fmt.Println("检查Ollama服务...")
    
    // 读取ip.csv中的IP列表
    ips, err := readFileLines("ip.csv")
    if err != nil {
        fmt.Printf("读取IP文件失败: %v\n", err) 
        return
    }

    // 创建进度条
    bar := newProgressBar(len(ips))
    
    ipChan := make(chan string, cfg.MaxWorkers)
    resultsChan := make(chan ScanResult, cfg.MaxWorkers)
    wg := sync.WaitGroup{}
    
    // 创建一个计数器用于进度条更新
    var completedCount int32
    
    // 启动workers
    for i := 0; i < cfg.MaxWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            client := initHttpClient(cfg.Timeout)
            
            for {
                select {
                case ip, ok := <-ipChan:
                    if !ok {
                        return
                    }
                    result := ScanResult{IP: ip}
                    
                    select {
                    case <-ctx.Done():
                        return
                    default:
                        // 检查端口是否开放
                        conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, cfg.Port), 1*time.Second)
                        if err != nil {
                            result.Status = "端口未开放"
                            resultsChan <- result
                            continue
                        }
                        conn.Close()
                        
                        // 检查Ollama服务状态
                        response, err := client.Get(fmt.Sprintf("http://%s:%d/api/version", ip, cfg.Port))
                        if err != nil {
                            result.Status = "服务无响应"  
                            resultsChan <- result
                            continue
                        }
                        
                        if response.StatusCode != http.StatusOK {
                            result.Status = fmt.Sprintf("HTTP状态码异常: %d", response.StatusCode)
                            response.Body.Close()
                            resultsChan <- result
                            continue
                        }
                        
                        // 获取模型列表
                        modelResponse, err := client.Get(fmt.Sprintf("http://%s:%d/api/tags", ip, cfg.Port))
                        if err != nil {
                            resultsChan <- result
                            continue
                        }
                        
                        var models []string
                        if err := json.NewDecoder(modelResponse.Body).Decode(&models); err != nil {
                            modelResponse.Body.Close()
                            resultsChan <- result
                            continue
                        }
                        modelResponse.Body.Close()
                        
                        // 排序模型列表
                        sort.Strings(models)
                        result.ModelNames = models

                        // 如果能获取到模型列表，说明服务正常
                        result.Status = "正常"
                        
                        // 更新进度条
                        count := atomic.AddInt32(&completedCount, 1)
                        bar.update(int(count))
                        
                        resultsChan <- result
                    }
                case <-ctx.Done():
                    return
                }
            }
        }()
    }
    
    // 处理结果的goroutine
    go func() {
        wg.Wait()
        close(resultsChan)
        bar.done()
    }()
    
    // 发送任务
    for _, ip := range ips {
        select {
        case <-ctx.Done():
            return
        case ipChan <- ip:
        }
    }
    close(ipChan)
    
    // 初始化CSV文件，准备写入结果
    initCSV(cfg)
    
    // 处理结果时同样需要考虑上下文取消
    for {
        select {
        case <-ctx.Done():
            return
        case result, ok := <-resultsChan:
            if !ok {
                return
            }
            if len(result.ModelNames) > 0 {
                processResult(result)
            }
        }
    }
}

// 菜单4相关函数，性能测试，获取模型列表，发送请求，处理响应，计算性能指标

// readCSV 读取ollama检测结果
func readCSV(filename string) ([]ScanResult, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    reader := csv.NewReader(file)
    // 跳过表头
    _, err = reader.Read()
    if err != nil {
        return nil, err
    }

    var results []ScanResult

    for {
        record, err := reader.Read()
        if err == io.EOF {
            break
        }
        if err != nil {
            return nil, err
        }

        // 只读取需要的列
        results = append(results, ScanResult{
            IP:         record[0],
            ModelNames: []string{record[1]},
            Status:     record[2],
        })
    }

    return results, nil
}

// benchmarkModel 性能测试
func benchmarkModel(ctx context.Context) {
    fmt.Println("开始性能测试...")
    
    // 读取csv文件
    existingResults, err := readCSV(cfg.OutputFile)
    if err != nil {
        fmt.Printf("读取现有结果失败: %v\n", err)
        return
    }

    // 过滤出可用的服务
    var availableResults []ScanResult
    for _, result := range existingResults {
        if result.Status == "正常" {
            availableResults = append(availableResults, result)
        }
    }

    // 备份原文件
    if err := os.Rename(cfg.OutputFile, cfg.OutputFile+".bak"); err != nil {
        fmt.Printf("备份文件失败: %v\n", err)
        return
    }

    // 创建进度条
    bar := newProgressBar(len(availableResults))
    var completedCount int32
    
    // 初始化新的CSV文件
    initCSV(cfg)
    
    var wg sync.WaitGroup
    
    // 创建工作池
    for i := 0; i < cfg.MaxWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            client := initHttpClient(cfg.BenchTimeout)
            
            for _, item := range availableResults {
                select {
                case <-ctx.Done():
                    return
                default:
                    firstTokenDelay, tokenSpeed := benchmarkSingleModel(ctx, item.IP, item.ModelNames[0], client)
                    
                    // 更新结果
                    item.FirstTokenDelay = firstTokenDelay
                    item.TokensPerSec = tokenSpeed
                    
                    // 更新进度条
                    count := atomic.AddInt32(&completedCount, 1)
                    bar.update(int(count))
                    
                    // 实时写入结果
                    processResult(item)
                }
            }
        }()
    }
    
    // 等待完成
    done := make(chan struct{})
    go func() {
        wg.Wait()
        bar.done()
        close(done)
    }()
    
    select {
    case <-ctx.Done():
        fmt.Println("\n性能测试被取消")
        return
    case <-done:
        fmt.Println("性能测试完成")
        os.Remove(cfg.OutputFile + ".bak")
    }
}

// benchmarkSingleModel 对单个模型进行性能测试
func benchmarkSingleModel(ctx context.Context, ip string, model string, client *http.Client) (time.Duration, float64) {
    startTime := time.Now()
    
    // 构建请求URL和请求体
    apiUrl := fmt.Sprintf("http://%s:%d/api/generate", ip, cfg.Port)
    requestBody := map[string]interface{}{
        "model": model,
        "prompt": cfg.BenchPrompt,
        "stream": true,
    }
    
    jsonBody, err := json.Marshal(requestBody)
    if err != nil {
        fmt.Printf("请求体编码失败: %v\n", err)
        return 0, 0
    }

    // 创建带有上下文的请求
    req, err := http.NewRequestWithContext(ctx, "POST", apiUrl, bytes.NewBuffer(jsonBody))
    if err != nil {
        fmt.Printf("创建请求失败: %v\n", err)
        return 0, 0
    }
    req.Header.Set("Content-Type", "application/json")

    response, err := client.Do(req)
    if err != nil {
        fmt.Printf("发送请求失败: %v\n", err)
        return 0, 0
    }
    defer response.Body.Close()

    // 用于跟踪性能指标
    var firstTokenTime time.Duration
    var totalTokens int
    decoder := json.NewDecoder(response.Body)
    isFirstToken := true
    tokenStartTime := time.Now()

    // 处理流式响应时要考虑上下文取消
    for {
        select {
        case <-ctx.Done():
            return 0, 0
        default:
            var streamResponse struct {
                Response string `json:"response"`
                Done     bool   `json:"done"`
            }

            if err := decoder.Decode(&streamResponse); err != nil {
                if err == io.EOF {
                    break
                }
                fmt.Printf("解码响应失败: %v\n", err)
                return 0, 0
            }

            if isFirstToken && len(streamResponse.Response) > 0 {
                firstTokenTime = time.Since(startTime)
                isFirstToken = false
            }

            if len(streamResponse.Response) > 0 {
                totalTokens += len(streamResponse.Response)
            }

            if streamResponse.Done {
                break
            }
        }
    }

    totalTime := time.Since(tokenStartTime).Seconds()
    tokensPerSecond := float64(totalTokens) / totalTime
    fmt.Printf("IP: %s, 模型: %s, 首token延迟: %s, Token速度: %.2f\n", ip, model, firstTokenTime, tokensPerSecond)

    return firstTokenTime, tokensPerSecond
}

// 共同使用函数

// initHttpClient 初始化普通HTTP客户端
func initHttpClient(timeout time.Duration) *http.Client {
    return &http.Client{
        Timeout: timeout,
        Transport: &http.Transport{
            MaxIdleConnsPerHost: 20,
            DisableKeepAlives:   false,
        },
    }
}

// 初始化CSV文件
func initCSV(cfg *Config) {
    csvFile, err := os.Create(cfg.OutputFile)
    if err != nil {
        fmt.Printf("创建CSV文件失败: %v\n", err)
        return
    }
    csvWriter = csv.NewWriter(csvFile)
    // 写入表头
    csvWriter.Write([]string{"IP", "模型名称", "服务状态", "首token延迟", "Token速度"})
}

// processResult 处理结果
func processResult(result ScanResult) {
    csvMutex.Lock()
    defer csvMutex.Unlock()
    
    for _, modelName := range result.ModelNames {
        csvWriter.Write([]string{
            result.IP,
            modelName,
            result.Status,
            result.FirstTokenDelay.String(),  // 转换为字符串格式
            fmt.Sprintf("%.2f", result.TokensPerSec), // 格式化为两位小数
        })
    }
    csvWriter.Flush()
}
