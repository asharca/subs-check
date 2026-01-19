package platform

import (
	"net/http"
)

func CheckClaude(httpClient *http.Client) (bool, error) {
	req, err := http.NewRequest("GET", "https://claude.ai/", nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

	// 不自动跟随重定向，手动检查
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: httpClient.Transport,
		Timeout:   httpClient.Timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// 检查是否有重定向
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		// 如果重定向到不可用页面，说明该地区不支持
		if location == "https://www.anthropic.com/app-unavailable-in-region" ||
		   location == "/app-unavailable-in-region" {
			return false, nil
		}
	}

	// 如果返回 200 或者没有重定向到不可用页面，说明可以访问
	if resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 301 {
		return true, nil
	}

	return false, nil
}
