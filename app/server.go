package app

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/beck-8/subs-check/check"
	"github.com/beck-8/subs-check/config"
	"github.com/beck-8/subs-check/save/method"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// 缓存结构
type checkResultCache struct {
	results   []check.Result
	timestamp time.Time
}

// 全局缓存，key为订阅链接
var resultCache = make(map[string]*checkResultCache)
var cacheMutex sync.RWMutex

// initHttpServer 初始化HTTP服务器
func (app *App) initHttpServer() error {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	saver, err := method.NewLocalSaver()
	if err != nil {
		return fmt.Errorf("获取http监听目录失败: %w", err)
	}

	// 动态订阅路由 - 支持通过URL参数指定订阅链接、流媒体和导出格式
	router.GET("/", app.dynamicSubscriptionHandler)

	// 静态文件路由 - 订阅服务相关，始终启用
	// 最初不应该不带路径，现在保持兼容
	router.StaticFile("/all.yaml", saver.OutputPath+"/all.yaml")
	router.StaticFile("/all.txt", saver.OutputPath+"/all.txt")
	router.StaticFile("/base64.txt", saver.OutputPath+"/base64.txt")
	router.StaticFile("/mihomo.yaml", saver.OutputPath+"/mihomo.yaml")
	router.StaticFile("/ACL4SSR_Online_Full.yaml", saver.OutputPath+"/ACL4SSR_Online_Full.yaml")
	// CM佬用的布丁狗
	router.StaticFile("/bdg.yaml", saver.OutputPath+"/bdg.yaml")

	router.Static("/sub/", saver.OutputPath)

	// 根据配置决定是否启用Web控制面板
	if config.GlobalConfig.EnableWebUI {
		if config.GlobalConfig.APIKey == "" {
			if apiKey := os.Getenv("API_KEY"); apiKey != "" {
				config.GlobalConfig.APIKey = apiKey
			} else {
				config.GlobalConfig.APIKey = GenerateSimpleKey()
				slog.Warn("未设置api-key，已生成一个随机api-key", "api-key", config.GlobalConfig.APIKey)
			}
		}
		slog.Info("启用Web控制面板", "path", "http://ip:port/admin", "api-key", config.GlobalConfig.APIKey)

		// 设置模板加载 - 只有在启用Web控制面板时才加载
		router.SetHTMLTemplate(template.Must(template.New("").ParseFS(configFS, "templates/*.html")))

		// API路由
		api := router.Group("/api")
		api.Use(app.authMiddleware(config.GlobalConfig.APIKey)) // 添加认证中间件
		{
			// 配置相关API
			api.GET("/config", app.getConfig)
			api.POST("/config", app.updateConfig)

			// 状态相关API
			api.GET("/status", app.getStatus)
			api.POST("/trigger-check", app.triggerCheckHandler)
			api.POST("/force-close", app.forceCloseHandler)
			// 版本相关API
			api.GET("/version", app.getVersion)

			// 日志相关API
			api.GET("/logs", app.getLogs)
		}

		// 配置页面
		router.GET("/admin", func(c *gin.Context) {
			c.HTML(http.StatusOK, "admin.html", gin.H{
				"configPath": app.configPath,
			})
		})
	} else {
		slog.Info("Web控制面板已禁用")
	}

	// 启动HTTP服务器
	go func() {
		for {
			if err := router.Run(config.GlobalConfig.ListenPort); err != nil {
				slog.Error(fmt.Sprintf("HTTP服务器启动失败，正在重启中: %v", err))
			}
			time.Sleep(30 * time.Second)
		}
	}()
	slog.Info("HTTP服务器启动", "port", config.GlobalConfig.ListenPort)
	return nil
}

// authMiddleware API认证中间件
func (app *App) authMiddleware(key string) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if subtle.ConstantTimeCompare([]byte(apiKey), []byte(key)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "无效的API密钥"})
			return
		}
		c.Next()
	}
}

// getConfig 获取配置文件内容
func (app *App) getConfig(c *gin.Context) {
	configData, err := os.ReadFile(app.configPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("读取配置文件失败: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"content": string(configData),
	})
}

// updateConfig 更新配置文件内容
func (app *App) updateConfig(c *gin.Context) {
	var req struct {
		Content string `json:"content"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求格式"})
		return
	}
	// 验证YAML格式
	var yamlData map[string]any
	if err := yaml.Unmarshal([]byte(req.Content), &yamlData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("YAML格式错误: %v", err)})
		return
	}

	// 写入新配置
	if err := os.WriteFile(app.configPath, []byte(req.Content), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("保存配置文件失败: %v", err)})
		return
	}

	// 配置文件监听器会自动重新加载配置
	c.JSON(http.StatusOK, gin.H{"message": "配置已更新"})
}

// getStatus 获取应用状态
func (app *App) getStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"checking":   app.checking.Load(),
		"proxyCount": check.ProxyCount.Load(),
		"available":  check.Available.Load(),
		"progress":   check.Progress.Load(),
	})
}

// triggerCheckHandler 手动触发检测
func (app *App) triggerCheckHandler(c *gin.Context) {
	app.TriggerCheck()
	c.JSON(http.StatusOK, gin.H{"message": "已触发检测"})
}

// forceCloseHandler 强制关闭
func (app *App) forceCloseHandler(c *gin.Context) {
	check.ForceClose.Store(true)
	c.JSON(http.StatusOK, gin.H{"message": "已强制关闭"})
}

// getLogs 获取最近日志
func (app *App) getLogs(c *gin.Context) {
	// 简单实现，从日志文件读取最后xx行
	logPath := TempLog()

	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		c.JSON(http.StatusOK, gin.H{"logs": []string{}})
		return
	}
	lines, err := ReadLastNLines(logPath, 100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("读取日志失败: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"logs": lines})
}

// getLogs 获取最近日志
func (app *App) getVersion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"version": app.version})
}

func ReadLastNLines(filePath string, n int) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	ring := make([]string, n)
	count := 0

	// 使用环形缓冲区读取
	for scanner.Scan() {
		ring[count%n] = scanner.Text()
		count++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// 处理结果
	if count <= n {
		return ring[:count], nil
	}

	// 调整顺序，从最旧到最新
	start := count % n
	result := append(ring[start:], ring[:start]...)
	return result, nil
}

func GenerateSimpleKey() string {
	return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
}

// dynamicSubscriptionHandler 动态订阅处理器
// 支持通过URL参数指定订阅链接、流媒体应用和导出格式
// 示例: http://localhost:8199?sub_link=https://example.com/sub&app=gemini&target=Clash&refresh=true
func (app *App) dynamicSubscriptionHandler(c *gin.Context) {
	subLink := c.Query("sub_link")
	appFilter := c.Query("app")
	target := c.Query("target")
	refresh := c.Query("refresh") == "true"

	// 如果没有任何参数，返回简单的使用说明
	if subLink == "" && appFilter == "" && target == "" {
		c.String(http.StatusOK, "动态订阅服务\n\n使用方法:\n?sub_link=订阅链接&app=流媒体应用&target=导出格式&refresh=true\n\n支持的流媒体应用: openai, gemini, netflix, disney, youtube\n支持的导出格式: Clash, ClashMeta, V2Ray, ShadowRocket, QX, sing-box, Surge, Surfboard, URI\n\nrefresh=true: 强制刷新缓存")
		return
	}

	// 获取检测结果
	results, err := app.getCheckResults(subLink, appFilter, refresh)
	if err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("获取节点失败: %v", err))
		return
	}

	// 根据流媒体应用过滤节点
	if appFilter != "" {
		results = app.filterResultsByApp(results, appFilter)
	}

	if len(results) == 0 {
		c.String(http.StatusOK, "没有找到符合条件的节点")
		return
	}

	// 提取节点列表
	proxies := make([]map[string]any, 0, len(results))
	for _, result := range results {
		proxies = append(proxies, result.Proxy)
	}

	// 如果没有指定target，返回YAML格式
	if target == "" {
		yamlData, err := yaml.Marshal(map[string]any{
			"proxies": proxies,
		})
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("生成YAML失败: %v", err))
			return
		}
		c.Data(http.StatusOK, "text/yaml; charset=utf-8", yamlData)
		return
	}

	// 标准化target参数（转换为标准格式）
	target = normalizeTarget(target)

	// 使用Sub-Store进行格式转换
	result, contentType, err := app.convertWithSubStore(proxies, target)
	if err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("格式转换失败: %v", err))
		return
	}

	c.Data(http.StatusOK, contentType, result)
}

// normalizeTarget 标准化target参数，不区分大小写
func normalizeTarget(target string) string {
	targetLower := strings.ToLower(target)

	// 映射到标准格式
	switch targetLower {
	case "clash":
		return "Clash"
	case "clashmeta":
		return "ClashMeta"
	case "v2ray":
		return "V2Ray"
	case "shadowrocket":
		return "ShadowRocket"
	case "qx", "quantumult":
		return "QX"
	case "sing-box", "singbox":
		return "sing-box"
	case "surge":
		return "Surge"
	case "surfboard":
		return "Surfboard"
	case "uri":
		return "URI"
	default:
		// 如果不匹配，返回首字母大写的格式
		if len(target) > 0 {
			return strings.ToUpper(target[:1]) + strings.ToLower(target[1:])
		}
		return target
	}
}

// getCheckResults 获取检测结果（带缓存）
func (app *App) getCheckResults(subLink string, appFilter string, refresh bool) ([]check.Result, error) {
	// 如果没有提供订阅链接，读取本地已保存的检测结果
	if subLink == "" {
		slog.Info("从本地文件读取检测结果")
		saver, err := method.NewLocalSaver()
		if err != nil {
			return nil, fmt.Errorf("获取本地保存器失败: %w", err)
		}

		// 读取all.yaml文件
		yamlFile, err := os.ReadFile(saver.OutputPath + "/all.yaml")
		if err != nil {
			return nil, fmt.Errorf("读取订阅文件失败: %w", err)
		}

		var data map[string]any
		if err := yaml.Unmarshal(yamlFile, &data); err != nil {
			return nil, fmt.Errorf("解析订阅文件失败: %w", err)
		}

		proxies, ok := data["proxies"].([]any)
		if !ok {
			return nil, fmt.Errorf("订阅文件格式错误")
		}

		slog.Info(fmt.Sprintf("从本地文件读取到 %d 个节点", len(proxies)))

		// 转换为Result列表（本地文件已经包含流媒体标记）
		results := make([]check.Result, 0, len(proxies))
		for i, p := range proxies {
			if proxy, ok := p.(map[string]any); ok {
				// 从节点名称解析流媒体支持情况
				result := check.Result{
					Proxy: proxy,
				}
				if name, ok := proxy["name"].(string); ok {
					if i < 3 {
						slog.Info(fmt.Sprintf("节点 %d 名称: %s", i+1, name))
					}
					result.Openai = strings.Contains(name, "GPT⁺")
					result.OpenaiWeb = strings.Contains(name, "GPT")
					result.Gemini = strings.Contains(name, "GM")
					result.Netflix = strings.Contains(name, "NF")
					result.Disney = strings.Contains(name, "D+")
					if idx := strings.Index(name, "YT-"); idx >= 0 {
						result.Youtube = name[idx+3:]
					}
					if idx := strings.Index(name, "TK-"); idx >= 0 {
						result.TikTok = name[idx+3:]
					}
				}
				results = append(results, result)
			}
		}

		return results, nil
	}

	// 构建缓存key（包含订阅链接和app参数）
	cacheKey := subLink
	if appFilter != "" {
		cacheKey = fmt.Sprintf("%s|app=%s", subLink, appFilter)
	}

	// 检查缓存（如果不是强制刷新）
	if !refresh {
		cacheMutex.RLock()
		if cached, ok := resultCache[cacheKey]; ok {
			// 缓存有效期30分钟
			if time.Since(cached.timestamp) < 30*time.Minute {
				cacheMutex.RUnlock()
				slog.Info(fmt.Sprintf("使用缓存结果，缓存时间: %v", cached.timestamp.Format("2006-01-02 15:04:05")))
				return cached.results, nil
			}
		}
		cacheMutex.RUnlock()
	} else {
		slog.Info("强制刷新，忽略缓存")
	}

	// 如果提供了订阅链接，需要进行完整的检测
	slog.Info(fmt.Sprintf("从订阅链接获取并检测: %s", subLink))

	// 临时保存原配置
	originalSubUrls := config.GlobalConfig.SubUrls
	originalMediaCheck := config.GlobalConfig.MediaCheck
	originalPlatforms := config.GlobalConfig.Platforms

	// 设置临时配置
	config.GlobalConfig.SubUrls = []string{subLink}
	config.GlobalConfig.MediaCheck = true

	// 根据appFilter参数决定检测哪些平台
	var platforms []string
	if appFilter != "" {
		// 只检测指定的平台
		switch appFilter {
		case "openai", "gpt":
			platforms = []string{"openai"}
		case "gemini", "gm":
			platforms = []string{"gemini"}
		case "netflix", "nf":
			platforms = []string{"netflix"}
		case "disney", "d+":
			platforms = []string{"disney"}
		case "youtube", "yt":
			platforms = []string{"youtube"}
		case "tiktok", "tk":
			platforms = []string{"tiktok"}
		default:
			// 如果是未知的app，检测所有平台
			platforms = []string{"openai", "youtube", "netflix", "disney", "gemini", "tiktok"}
		}
	} else {
		// 如果没有指定app，检测所有平台
		platforms = []string{"openai", "youtube", "netflix", "disney", "gemini", "tiktok"}
	}

	config.GlobalConfig.Platforms = platforms

	slog.Info(fmt.Sprintf("临时配置已设置: MediaCheck=true, Platforms=%v", platforms))

	// 执行完整的检测流程
	results, err := check.Check()

	// 恢复原配置
	config.GlobalConfig.SubUrls = originalSubUrls
	config.GlobalConfig.MediaCheck = originalMediaCheck
	config.GlobalConfig.Platforms = originalPlatforms

	if err != nil {
		return nil, fmt.Errorf("检测失败: %w", err)
	}

	slog.Info(fmt.Sprintf("检测完成，可用节点数: %d", len(results)))

	// 打印前几个节点的流媒体支持情况
	for i, result := range results {
		if i >= 3 {
			break
		}
		if name, ok := result.Proxy["name"].(string); ok {
			slog.Info(fmt.Sprintf("节点 %d: %s, Gemini=%v, Netflix=%v, Disney=%v, OpenAI=%v",
				i+1, name, result.Gemini, result.Netflix, result.Disney, result.Openai))
		}
	}

	// 保存到缓存
	cacheMutex.Lock()
	resultCache[cacheKey] = &checkResultCache{
		results:   results,
		timestamp: time.Now(),
	}
	cacheMutex.Unlock()
	slog.Info(fmt.Sprintf("结果已缓存，key: %s", cacheKey))

	return results, nil
}

// filterResultsByApp 根据流媒体应用过滤检测结果
func (app *App) filterResultsByApp(results []check.Result, appName string) []check.Result {
	filtered := make([]check.Result, 0)

	slog.Info(fmt.Sprintf("开始过滤，应用: %s, 总节点数: %d", appName, len(results)))

	for _, result := range results {
		matched := false
		switch appName {
		case "openai", "gpt":
			if result.Openai || result.OpenaiWeb {
				matched = true
			}
		case "gemini", "gm":
			if result.Gemini {
				matched = true
			}
		case "netflix", "nf":
			if result.Netflix {
				matched = true
			}
		case "disney", "d+":
			if result.Disney {
				matched = true
			}
		case "youtube", "yt":
			if result.Youtube != "" {
				matched = true
			}
		case "tiktok", "tk":
			if result.TikTok != "" {
				matched = true
			}
		}

		if matched {
			if name, ok := result.Proxy["name"].(string); ok {
				slog.Info(fmt.Sprintf("匹配到节点: %s", name))
			}
			filtered = append(filtered, result)
		}
	}

	slog.Info(fmt.Sprintf("过滤完成，匹配节点数: %d", len(filtered)))
	return filtered
}

// convertWithSubStore 使用Sub-Store进行格式转换
func (app *App) convertWithSubStore(proxies []map[string]any, target string) ([]byte, string, error) {
	// 检查Sub-Store是否配置
	if config.GlobalConfig.SubStorePort == "" {
		return nil, "", fmt.Errorf("Sub-Store未配置，请在配置文件中设置sub-store-port")
	}

	// 生成临时订阅YAML
	yamlData, err := yaml.Marshal(map[string]any{
		"proxies": proxies,
	})
	if err != nil {
		return nil, "", fmt.Errorf("生成YAML失败: %w", err)
	}

	// 创建临时订阅名称
	tempSubName := fmt.Sprintf("temp_%d", time.Now().UnixNano())

	// 格式化端口
	port := config.GlobalConfig.SubStorePort
	if !strings.HasPrefix(port, ":") {
		if strings.Contains(port, ":") {
			parts := strings.Split(port, ":")
			port = ":" + parts[len(parts)-1]
		} else {
			port = ":" + port
		}
	}

	baseURL := fmt.Sprintf("http://127.0.0.1%s", port)
	if config.GlobalConfig.SubStorePath != "" {
		baseURL = fmt.Sprintf("%s%s", baseURL, config.GlobalConfig.SubStorePath)
	}

	// 创建临时订阅
	subData := map[string]any{
		"content": string(yamlData),
		"name":    tempSubName,
		"remark":  "临时订阅",
		"source":  "local",
		"process": []map[string]any{
			{
				"type": "Quick Setting Operator",
			},
		},
	}

	jsonData, err := json.Marshal(subData)
	if err != nil {
		return nil, "", fmt.Errorf("序列化订阅数据失败: %w", err)
	}

	// 发送创建请求
	resp, err := http.Post(fmt.Sprintf("%s/api/subs", baseURL), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, "", fmt.Errorf("创建临时订阅失败: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, "", fmt.Errorf("创建临时订阅失败，状态码: %d", resp.StatusCode)
	}

	// 延迟删除临时订阅
	defer func() {
		req, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/sub/%s", baseURL, tempSubName), nil)
		http.DefaultClient.Do(req)
	}()

	// 请求转换后的订阅
	downloadURL := fmt.Sprintf("%s/download/%s", baseURL, tempSubName)
	if target != "" {
		downloadURL = fmt.Sprintf("%s?target=%s", downloadURL, target)
	}

	resp, err = http.Get(downloadURL)
	if err != nil {
		return nil, "", fmt.Errorf("获取转换后的订阅失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("获取转换后的订阅失败，状态码: %d, 错误: %s", resp.StatusCode, string(body))
	}

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("读取转换结果失败: %w", err)
	}

	// 根据target确定Content-Type
	contentType := "text/plain; charset=utf-8"
	switch target {
	case "Clash", "ClashMeta":
		contentType = "text/yaml; charset=utf-8"
	case "sing-box":
		contentType = "application/json; charset=utf-8"
	}

	return result, contentType, nil
}
