package platform

import (
	"io"
	"net/http"
	"strings"
)

func CheckClaude(httpClient *http.Client) (bool, error) {
	req, err := http.NewRequest("GET", "https://claude.ai/", nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// 检查最终的 URL（跟随重定向后）
	finalURL := resp.Request.URL.String()

	// 如果重定向到不可用页面，说明该地区不支持
	if strings.Contains(finalURL, "app-unavailable-in-region") {
		return false, nil
	}

	// 如果最终 URL 是 claude.ai，说明可以访问
	if strings.Contains(finalURL, "claude.ai") && resp.StatusCode == 200 {
		return true, nil
	}

	// 读取响应体检查是否包含 claude.ai 的内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	// 如果响应体包含 claude 相关内容，说明可以访问
	bodyStr := string(body)
	if strings.Contains(bodyStr, "claude") || strings.Contains(bodyStr, "anthropic") {
		return true, nil
	}

	return false, nil
}
