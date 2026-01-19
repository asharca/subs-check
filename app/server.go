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
	"regexp"
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

	// 设置模板加载 - 动态订阅页面需要使用模板
	router.SetHTMLTemplate(template.Must(template.New("").ParseFS(configFS, "templates/*.html")))

	// 动态订阅路由 - 支持通过URL参数指定订阅链接、流媒体和导出格式
	router.GET("/", app.dynamicSubscriptionHandler)

	// 公开API - 供动态订阅页面使用，无需认证
	publicApi := router.Group("/public-api")
	{
		publicApi.GET("/logs", app.getLogs)
		publicApi.GET("/status", app.getStatus)
	}

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
// 示例: http://localhost:8199?sub_link=https://example.com/sub&app=gemini,netflix&tags={"gemini":"§gemini§","netflix":"§netflix§"}&target=Clash&refresh=true
func (app *App) dynamicSubscriptionHandler(c *gin.Context) {
	subLink := c.Query("sub_link")
	appFilter := c.Query("app")
	target := c.Query("target")
	refresh := c.Query("refresh") == "true"
	tagsJSON := c.Query("tags") // 平台标签的 JSON 字符串

	// 解析平台标签
	var platformTags map[string]string
	if tagsJSON != "" {
		if err := json.Unmarshal([]byte(tagsJSON), &platformTags); err != nil {
			slog.Warn(fmt.Sprintf("解析平台标签失败: %v", err))
			platformTags = nil
		}
	}

	// 兼容旧的 suffix 参数（如果没有提供 tags，则使用 suffix 作为所有平台的统一标签）
	customTag := c.Query("suffix")
	if customTag == "" {
		customTag = c.Query("tag")
	}

	// 当 app=all 且没有提供任何标签时，为每个平台设置默认标签 §平台名§
	if appFilter == "all" && tagsJSON == "" && customTag == "" {
		platformTags = map[string]string{
			"openai":  "§openai§",
			"gemini":  "§gemini§",
			"claude":  "§claude§",
			"netflix": "§netflix§",
			"disney":  "§disney§",
			"youtube": "§youtube§",
			"tiktok":  "§tiktok§",
		}
	}

	// 如果 app=all，展开为所有支持的平台
	if appFilter == "all" {
		appFilter = "openai,gemini,claude,netflix,disney,youtube,tiktok"
	}

	// 如果没有任何参数，显示HTML表单页面
	if subLink == "" && appFilter == "" && target == "" && tagsJSON == "" && customTag == "" {
		c.HTML(http.StatusOK, "dynamic_sub.html", nil)
		return
	}

	// 获取检测结果
	results, err := app.getCheckResults(subLink, appFilter, refresh, platformTags, customTag)
	if err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("获取节点失败: %v", err))
		return
	}

	originalCount := len(results)
	originalResults := results // 保存原始结果

	// 根据流媒体应用过滤节点
	var filteredResults []check.Result
	if appFilter != "" {
		filteredResults = app.filterResultsByApp(results, appFilter)
	} else {
		filteredResults = results
	}

	// 提取节点列表
	proxies := make([]map[string]any, 0)

	// 如果过滤后没有符合条件的节点，但有可用节点
	if len(filteredResults) == 0 && originalCount > 0 && appFilter != "" {
		// 返回所有可用节点
		for _, result := range originalResults {
			proxies = append(proxies, result.Proxy)
		}

		// 添加一个假节点作为提示信息
		noticeProxy := map[string]any{
			"name":     fmt.Sprintf("⚠️ 没有支持 %s 的节点", appFilter),
			"type":     "ss",
			"server":   "127.0.0.1",
			"port":     1080,
			"cipher":   "aes-128-gcm",
			"password": "notice",
			"udp":      false,
		}
		proxies = append([]map[string]any{noticeProxy}, proxies...)

	} else if len(filteredResults) == 0 && originalCount == 0 {
		// 完全没有可用节点
		noticeProxy := map[string]any{
			"name":     "⚠️ 没有找到可用节点",
			"type":     "ss",
			"server":   "127.0.0.1",
			"port":     1080,
			"cipher":   "aes-128-gcm",
			"password": "notice",
			"udp":      false,
		}
		proxies = append(proxies, noticeProxy)

	} else {
		// 有符合条件的节点，正常返回
		for _, result := range filteredResults {
			proxies = append(proxies, result.Proxy)
		}
		results = filteredResults
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
		c.String(http.StatusInternalServerError, fmt.Sprintf("格式转换失败: %v\n\n可能原因:\n1. Sub-Store 服务未启动或配置错误\n2. 目标格式不支持\n3. 节点配置与目标格式不兼容\n\n建议:\n- 检查 sub-store-port 配置是否正确\n- 确认 Sub-Store 服务正在运行\n- 尝试使用其他导出格式\n- 查看 Sub-Store 日志获取详细错误", err))
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
	case "mihomo":
		return "mihomo" // 特殊处理，使用小写
	case "openwrt":
		return "openwrt" // 特殊处理，基于 mihomo 添加 OpenWrt 配置
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
func (app *App) getCheckResults(subLink string, appFilter string, refresh bool, platformTags map[string]string, customTag string) ([]check.Result, error) {
	// 如果没有提供订阅链接，读取本地已保存的检测结果
	if subLink == "" {
		slog.Info("从本地文件读取检测结果")
		saver, err := method.NewLocalSaver()
		if err != nil {
			return nil, fmt.Errorf("获取本地保存器失败: %w\n\n请检查配置文件中的 output-dir 设置", err)
		}

		// 读取all.yaml文件
		yamlFile, err := os.ReadFile(saver.OutputPath + "/all.yaml")
		if err != nil {
			return nil, fmt.Errorf("读取订阅文件失败: %w\n\n可能原因:\n1. 尚未执行过节点检测\n2. 输出目录不存在或无权限访问\n3. all.yaml 文件已被删除\n\n建议:\n- 先执行一次完整的节点检测\n- 检查 output-dir 配置是否正确\n- 确认程序有读取该目录的权限", err)
		}

		var data map[string]any
		if err := yaml.Unmarshal(yamlFile, &data); err != nil {
			return nil, fmt.Errorf("解析订阅文件失败: %w\n\nall.yaml 文件可能已损坏，建议重新执行节点检测", err)
		}

		proxies, ok := data["proxies"].([]any)
		if !ok {
			return nil, fmt.Errorf("订阅文件格式错误: 缺少 proxies 字段或格式不正确\n\nall.yaml 文件可能已损坏，建议重新执行节点检测")
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
					result.Claude = strings.Contains(name, "CL")
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

		// 如果指定了平台标签或自定义标签，需要重新处理节点名称
		if (platformTags != nil && len(platformTags) > 0) || (customTag != "" && appFilter != "") {
			// 为匹配的节点重新添加自定义标签
			for i := range results {
				result := &results[i]
				if name, ok := result.Proxy["name"].(string); ok {
					// 移除所有已有标签
					name = regexp.MustCompile(`\s*\|.*$`).ReplaceAllString(name, "")
					name = strings.TrimSpace(name)

					// 根据检测结果决定是否添加自定义标签
					// 收集该节点支持的所有平台标签
					var tags []string

					// 解析多个平台参数
					appList := strings.Split(appFilter, ",")
					for _, platform := range appList {
						platform = strings.TrimSpace(platform)

						// 获取该平台的自定义标签
						var tag string
						if platformTags != nil {
							tag = platformTags[platform]
						}
						if tag == "" && customTag != "" {
							tag = customTag // 回退到统一标签
						}

						if tag == "" {
							continue // 没有标签则跳过
						}

						switch platform {
						case "openai", "gpt":
							if result.Openai || result.OpenaiWeb {
								tags = append(tags, tag)
							}
						case "gemini", "gm":
							if result.Gemini {
								tags = append(tags, tag)
							}
						case "claude", "cl":
							if result.Claude {
								tags = append(tags, tag)
							}
						case "netflix", "nf":
							if result.Netflix {
								tags = append(tags, tag)
							}
						case "disney", "d+":
							if result.Disney {
								tags = append(tags, tag)
							}
						case "youtube", "yt":
							if result.Youtube != "" {
								tags = append(tags, tag+"-"+result.Youtube)
							}
						case "tiktok", "tk":
							if result.TikTok != "" {
								tags = append(tags, tag+"-"+result.TikTok)
							}
						}
					}

					// 如果有匹配的标签，添加到节点名称
					if len(tags) > 0 {
						name += "|" + strings.Join(tags, "|")
					}

					result.Proxy["name"] = name
				}
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
	originalPlatformTags := config.GlobalConfig.PlatformTags

	// 设置临时配置
	config.GlobalConfig.SubUrls = []string{subLink}
	config.GlobalConfig.MediaCheck = true

	// 注意：不在这里设置 PlatformTags，而是在检测完成后手动添加自定义标签

	// 根据appFilter参数决定检测哪些平台
	var platforms []string
	if appFilter != "" {
		// 支持逗号分隔的多个平台
		appList := strings.Split(appFilter, ",")
		platformSet := make(map[string]bool) // 用于去重

		for _, app := range appList {
			app = strings.TrimSpace(app)
			switch app {
			case "openai", "gpt":
				platformSet["openai"] = true
			case "gemini", "gm":
				platformSet["gemini"] = true
			case "netflix", "nf":
				platformSet["netflix"] = true
			case "disney", "d+":
				platformSet["disney"] = true
			case "youtube", "yt":
				platformSet["youtube"] = true
			case "tiktok", "tk":
				platformSet["tiktok"] = true
			default:
				// 如果是未知的app，跳过
				slog.Warn(fmt.Sprintf("未知的平台参数: %s", app))
			}
		}

		// 如果没有识别到任何有效平台，检测所有平台
		if len(platformSet) == 0 {
			platforms = []string{"openai", "youtube", "netflix", "disney", "gemini", "tiktok"}
		} else {
			// 转换为切片
			for platform := range platformSet {
				platforms = append(platforms, platform)
			}
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
	config.GlobalConfig.PlatformTags = originalPlatformTags

	if err != nil {
		return nil, fmt.Errorf("检测失败: %w\n\n可能原因:\n1. 订阅链接无法访问\n2. 订阅内容格式错误\n3. 网络连接问题\n\n建议检查订阅链接是否正确，或查看日志获取详细错误", err)
	}

	slog.Info(fmt.Sprintf("检测完成，可用节点数: %d", len(results)))

	// 打印前几个节点的流媒体支持情况
	for i, result := range results {
		if name, ok := result.Proxy["name"].(string); ok {
			slog.Info(fmt.Sprintf("节点 %d: %s, Gemini=%v, Netflix=%v, Disney=%v, OpenAI=%v",
				i+1, name, result.Gemini, result.Netflix, result.Disney, result.Openai))
		}
	}

	// 如果提供了平台标签或自定义标签，为节点添加多平台标签
	if (platformTags != nil && len(platformTags) > 0) || (customTag != "" && appFilter != "") {
		results = app.addMultiPlatformTagsWithMap(results, appFilter, platformTags, customTag)
		slog.Info("已添加自定义多平台标签")
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

// filterResultsByApp 根据流媒体应用过滤检测结果（支持多平台）
func (app *App) filterResultsByApp(results []check.Result, appName string) []check.Result {
	filtered := make([]check.Result, 0)

	// 解析多个平台参数（逗号分隔）
	appList := strings.Split(appName, ",")
	platformMap := make(map[string]bool)
	for _, a := range appList {
		a = strings.TrimSpace(a)
		if a != "" {
			platformMap[a] = true
		}
	}

	slog.Info(fmt.Sprintf("开始过滤，应用: %s, 总节点数: %d", appName, len(results)))

	for _, result := range results {
		matched := false

		// 检查节点是否匹配任一选中的平台
		for platform := range platformMap {
			switch platform {
			case "openai", "gpt":
				if result.Openai || result.OpenaiWeb {
					matched = true
				}
			case "gemini", "gm":
				if result.Gemini {
					matched = true
				}
			case "claude", "cl":
				if result.Claude {
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

			// 只要匹配任一平台就添加该节点
			if matched {
				break
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
		return nil, "", fmt.Errorf("Sub-Store未配置\n\n请在配置文件中设置 sub-store-port 参数\n例如: sub-store-port: \"3001\"")
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
		return nil, "", fmt.Errorf("创建临时订阅失败: %w\n\n请检查:\n1. Sub-Store 服务是否正在运行\n2. sub-store-port 配置是否正确 (当前: %s)\n3. 防火墙是否阻止了连接", err, config.GlobalConfig.SubStorePort)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, "", fmt.Errorf("创建临时订阅失败，状态码: %d\n\nSub-Store 服务可能未正常运行或配置错误", resp.StatusCode)
	}

	// 延迟删除临时订阅
	defer func() {
		req, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/sub/%s", baseURL, tempSubName), nil)
		http.DefaultClient.Do(req)
	}()

	// 请求转换后的订阅
	var downloadURL string
	var contentType string

	// mihomo 和 openwrt 格式需要特殊处理，需要创建 file 而不是 sub
	if target == "mihomo" || target == "openwrt" {
		// 创建临时 mihomo file
		tempFileName := fmt.Sprintf("temp_mihomo_%d", time.Now().UnixNano())

		// mihomo file 需要 Script Operator，但对于动态订阅我们可以使用空配置或默认配置
		// 如果用户配置了 mihomo-overwrite-url，使用它；否则使用空配置
		var processConfig []map[string]any
		if config.GlobalConfig.MihomoOverwriteUrl != "" {
			processConfig = []map[string]any{
				{
					"type": "Script Operator",
					"args": map[string]any{
						"mode":    "link",
						"content": config.GlobalConfig.MihomoOverwriteUrl,
					},
					"disabled": false,
				},
			}
		} else {
			// 使用空的 process，让 Sub-Store 生成基础的 mihomo 配置
			processConfig = []map[string]any{}
		}

		fileData := map[string]any{
			"name":       tempFileName,
			"remark":     "临时mihomo配置",
			"source":     "local",
			"sourceName": tempSubName,
			"sourceType": "subscription",
			"type":       "mihomoProfile",
			"process":    processConfig,
		}

		fileJsonData, err := json.Marshal(fileData)
		if err != nil {
			return nil, "", fmt.Errorf("序列化mihomo文件数据失败: %w", err)
		}

		// 创建 mihomo file
		resp, err := http.Post(fmt.Sprintf("%s/api/files", baseURL), "application/json", bytes.NewBuffer(fileJsonData))
		if err != nil {
			return nil, "", fmt.Errorf("创建临时mihomo文件失败: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			return nil, "", fmt.Errorf("创建临时mihomo文件失败，状态码: %d，错误: %s", resp.StatusCode, string(body))
		}

		// 延迟删除临时 mihomo file
		defer func() {
			req, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/file/%s", baseURL, tempFileName), nil)
			http.DefaultClient.Do(req)
		}()

		downloadURL = fmt.Sprintf("%s/api/file/%s", baseURL, tempFileName)
		contentType = "text/yaml; charset=utf-8"
	} else {
		downloadURL = fmt.Sprintf("%s/download/%s", baseURL, tempSubName)
		if target != "" {
			downloadURL = fmt.Sprintf("%s?target=%s", downloadURL, target)
		}
		// 根据target确定Content-Type
		contentType = "text/plain; charset=utf-8"
		switch target {
		case "Clash", "ClashMeta":
			contentType = "text/yaml; charset=utf-8"
		case "sing-box":
			contentType = "application/json; charset=utf-8"
		}
	}

	resp, err = http.Get(downloadURL)
	if err != nil {
		return nil, "", fmt.Errorf("获取转换后的订阅失败: %w\n\n请检查 Sub-Store 服务是否正常", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("获取转换后的订阅失败，状态码: %d\n错误信息: %s\n\n可能原因:\n1. 目标格式 '%s' 不支持或拼写错误\n2. 节点配置与目标格式不兼容\n3. mihomo/openwrt 格式需要配置 mihomo-overwrite-url\n\n支持的格式: Clash, ClashMeta, Mihomo, OpenWrt, V2Ray, ShadowRocket, QX, sing-box, Surge, Surfboard, URI", resp.StatusCode, string(body), target)
	}

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("读取转换结果失败: %w", err)
	}

	// 如果是 openwrt 格式，在顶部添加 OpenWrt 基础配置
	if target == "openwrt" {
		openWrtHeader := `# --- 基础设置开始 ---
port: 7890
socks-port: 7891
mixed-port: 7893 # 混合端口(HTTP+SOCKS)，OpenWrt常用
allow-lan: true # 允许局域网设备连接
mode: Rule # 模式：Rule(规则) / Global(全局) / Direct(直连)
log-level: info # 日志等级
external-controller: :9090 # 外部控制端口
# --- 基础设置结束 ---

`
		result = append([]byte(openWrtHeader), result...)
	}

	return result, contentType, nil
}

// addPlatformTags 根据指定的平台列表为节点添加标记
func (app *App) addPlatformTags(results []check.Result, platforms []string) []check.Result {
	for i := range results {
		result := &results[i]
		if name, ok := result.Proxy["name"].(string); ok {
			// 移除已有的流媒体标记
			name = regexp.MustCompile(`\s*\|(?:NF|D\+|GPT⁺|GPT|GM|YT-[^|]+|TK-[^|]+|\d+%)`).ReplaceAllString(name, "")
			name = strings.TrimSpace(name)

			var tags []string

			// 按指定的平台顺序添加标记
			for _, plat := range platforms {
				switch plat {
				case "openai", "gpt":
					if result.Openai {
						tags = append(tags, config.GetPlatformTag("openai", "GPT⁺"))
					} else if result.OpenaiWeb {
						tags = append(tags, config.GetPlatformTag("openai-web", "GPT"))
					}
				case "netflix", "nf":
					if result.Netflix {
						tags = append(tags, config.GetPlatformTag("netflix", "NF"))
					}
				case "disney", "d+":
					if result.Disney {
						tags = append(tags, config.GetPlatformTag("disney", "D+"))
					}
				case "gemini", "gm":
					if result.Gemini {
						tags = append(tags, config.GetPlatformTag("gemini", "GM"))
					}
				case "youtube", "yt":
					if result.Youtube != "" {
						tagPrefix := config.GetPlatformTag("youtube", "YT")
						tags = append(tags, fmt.Sprintf("%s-%s", tagPrefix, result.Youtube))
					}
				case "tiktok", "tk":
					if result.TikTok != "" {
						tagPrefix := config.GetPlatformTag("tiktok", "TK")
						tags = append(tags, fmt.Sprintf("%s-%s", tagPrefix, result.TikTok))
					}
				}
			}

			// 将标记添加到名称中
			if len(tags) > 0 {
				name += "|" + strings.Join(tags, "|")
			}

			result.Proxy["name"] = name
		}
	}
	return results
}

// addCustomPlatformTags 使用自定义标签为节点添加标记
func (app *App) addCustomPlatformTags(results []check.Result, appFilter string, customTag string) []check.Result {
	for i := range results {
		result := &results[i]
		if name, ok := result.Proxy["name"].(string); ok {
			// 移除已有的流媒体标记
			name = regexp.MustCompile(`\s*\|(?:NF|D\+|GPT⁺|GPT|GM|YT-[^|]+|TK-[^|]+|\d+%)`).ReplaceAllString(name, "")
			// 也移除可能的自定义标签（emoji等）
			name = regexp.MustCompile(`\s*\|[^|]+`).ReplaceAllString(name, "")
			name = strings.TrimSpace(name)

			var tag string

			// 根据appFilter和检测结果决定是否添加标签
			switch appFilter {
			case "openai", "gpt":
				if result.Openai || result.OpenaiWeb {
					tag = customTag
				}
			case "netflix", "nf":
				if result.Netflix {
					tag = customTag
				}
			case "disney", "d+":
				if result.Disney {
					tag = customTag
				}
			case "gemini", "gm":
				if result.Gemini {
					tag = customTag
				}
			case "youtube", "yt":
				if result.Youtube != "" {
					// YouTube 需要添加地区后缀
					tag = fmt.Sprintf("%s-%s", customTag, result.Youtube)
				}
			case "tiktok", "tk":
				if result.TikTok != "" {
					// TikTok 需要添加地区后缀
					tag = fmt.Sprintf("%s-%s", customTag, result.TikTok)
				}
			}

			// 将标记添加到名称中
			if tag != "" {
				name += "|" + tag
			}

			result.Proxy["name"] = name
		}
	}
	return results
}

// addMultiPlatformTags 为节点添加多平台标签（支持一个节点显示多个平台标签）
func (app *App) addMultiPlatformTags(results []check.Result, appFilter string, customTag string) []check.Result {
	// 解析多个平台参数
	appList := strings.Split(appFilter, ",")

	for i := range results {
		result := &results[i]
		if name, ok := result.Proxy["name"].(string); ok {
			// 移除已有的流媒体标记
			name = regexp.MustCompile(`\s*\|(?:NF|D\+|GPT⁺|GPT|GM|YT-[^|]+|TK-[^|]+|\d+%)`).ReplaceAllString(name, "")
			name = strings.TrimSpace(name)

			// 收集该节点支持的所有平台标签
			var tags []string

			for _, platform := range appList {
				platform = strings.TrimSpace(platform)
				switch platform {
				case "openai", "gpt":
					if result.Openai {
						tags = append(tags, customTag+"-GPT⁺")
					} else if result.OpenaiWeb {
						tags = append(tags, customTag+"-GPT")
					}
				case "gemini", "gm":
					if result.Gemini {
						tags = append(tags, customTag+"-GM")
					}
				case "netflix", "nf":
					if result.Netflix {
						tags = append(tags, customTag+"-NF")
					}
				case "disney", "d+":
					if result.Disney {
						tags = append(tags, customTag+"-D+")
					}
				case "youtube", "yt":
					if result.Youtube != "" {
						tags = append(tags, customTag+"-YT-"+result.Youtube)
					}
				case "tiktok", "tk":
					if result.TikTok != "" {
						tags = append(tags, customTag+"-TK-"+result.TikTok)
					}
				}
			}

			// 如果有匹配的标签，添加到节点名称
			if len(tags) > 0 {
				name += "|" + strings.Join(tags, "|")
			}

			result.Proxy["name"] = name
		}
	}
	return results
}

// addMultiPlatformTagsWithMap 为节点添加多平台标签（支持每个平台独立的自定义标签）
func (app *App) addMultiPlatformTagsWithMap(results []check.Result, appFilter string, platformTags map[string]string, fallbackTag string) []check.Result {
	// 解析多个平台参数
	appList := strings.Split(appFilter, ",")

	for i := range results {
		result := &results[i]
		if name, ok := result.Proxy["name"].(string); ok {
			// 移除已有的流媒体标记
			name = regexp.MustCompile(`\s*\|(?:NF|D\+|GPT⁺|GPT|GM|YT-[^|]+|TK-[^|]+|\d+%)`).ReplaceAllString(name, "")
			name = strings.TrimSpace(name)

			// 收集该节点支持的所有平台标签
			var tags []string

			for _, platform := range appList {
				platform = strings.TrimSpace(platform)

				// 获取该平台的自定义标签
				var tag string
				if platformTags != nil {
					tag = platformTags[platform]
				}
				if tag == "" && fallbackTag != "" {
					tag = fallbackTag // 回退到统一标签
				}

				if tag == "" {
					continue // 没有标签则跳过
				}

				switch platform {
				case "openai", "gpt":
					if result.Openai || result.OpenaiWeb {
						tags = append(tags, tag)
					}
				case "gemini", "gm":
					if result.Gemini {
						tags = append(tags, tag)
					}
				case "netflix", "nf":
					if result.Netflix {
						tags = append(tags, tag)
					}
				case "disney", "d+":
					if result.Disney {
						tags = append(tags, tag)
					}
				case "youtube", "yt":
					if result.Youtube != "" {
						tags = append(tags, tag+"-"+result.Youtube)
					}
				case "tiktok", "tk":
					if result.TikTok != "" {
						tags = append(tags, tag+"-"+result.TikTok)
					}
				}
			}

			// 如果有匹配的标签，添加到节点名称
			if len(tags) > 0 {
				name += "|" + strings.Join(tags, "|")
			}

			result.Proxy["name"] = name
		}
	}
	return results
}
