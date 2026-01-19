package platform

import (
	"io"
	"net/http"
	"strings"
)

// Netflix 检测常量 - 参考 netflix-verify 项目
const (
	// 地区可用 ID - 用于检测地区是否开通 Netflix 服务
	AreaAvailableID = 80018499
	// 自制剧 ID - 用于检测是否解锁自制内容
	SelfMadeAvailableID = 80197526
	// 非自制剧 ID - 用于检测是否解锁第三方版权内容（完全解锁的标志）
	NonSelfMadeAvailableID = 70143836
)

// Netflix 解锁状态
const (
	NetworkUnreachable      = -2 // 网络不可达
	AreaUnavailable         = -1 // 地区不可用
	AreaAvailable           = 0  // 地区可用但未解锁
	UnblockSelfMadeMovie    = 1  // 解锁自制剧
	UnblockNonSelfMadeMovie = 2  // 解锁非自制剧（完全解锁）
)

// UnblockTestResult 解锁测试结果
type UnblockTestResult struct {
	movieID   int
	available bool
	err       error
}

// CheckNetflix 检测 Netflix 是否完全解锁（能看非自制剧）
// 返回 true 表示完全解锁，可以观看所有影片（包括第三方版权内容）
// 参考 netflix-verify 项目的检测逻辑
func CheckNetflix(httpClient *http.Client) (bool, error) {
	unblockStatus := AreaUnavailable
	testChan := make(chan UnblockTestResult, 3)

	// 并发检测三个影片 ID
	go unblockTest(httpClient, AreaAvailableID, testChan)
	go unblockTest(httpClient, SelfMadeAvailableID, testChan)
	go unblockTest(httpClient, NonSelfMadeAvailableID, testChan)

	// 收集三个测试结果
	var firstError error
	for i := 0; i < 3; i++ {
		res := <-testChan

		// 记录第一个错误，但继续接收其他结果，避免 goroutine 泄漏
		if res.err != nil && firstError == nil {
			firstError = res.err
		}

		// 根据测试结果更新解锁状态
		if res.available {
			switch res.movieID {
			case AreaAvailableID:
				// 地区可用
				if unblockStatus < AreaAvailable {
					unblockStatus = AreaAvailable
				}
			case SelfMadeAvailableID:
				// 解锁自制剧
				if unblockStatus < UnblockSelfMadeMovie {
					unblockStatus = UnblockSelfMadeMovie
				}
			case NonSelfMadeAvailableID:
				// 解锁非自制剧（完全解锁）
				if unblockStatus < UnblockNonSelfMadeMovie {
					unblockStatus = UnblockNonSelfMadeMovie
				}
			}
		}
	}

	close(testChan)

	// 如果有错误，返回错误
	if firstError != nil {
		return false, firstError
	}

	// 只有达到 UnblockNonSelfMadeMovie 状态才算完全解锁
	// 这意味着可以观看所有影片，包括第三方版权内容
	return unblockStatus >= UnblockNonSelfMadeMovie, nil
}

// unblockTest 测试指定影片是否可访问
func unblockTest(httpClient *http.Client, movieID int, resultChan chan UnblockTestResult) {
	url := "https://www.netflix.com/title/" + intToString(movieID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		resultChan <- UnblockTestResult{movieID, false, err}
		return
	}

	// 设置请求头，模拟真实浏览器
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

	resp, err := httpClient.Do(req)
	if err != nil {
		resultChan <- UnblockTestResult{movieID, false, err}
		return
	}
	defer resp.Body.Close()

	// 状态码 200 表示可以访问该影片
	if resp.StatusCode == 200 {
		// 读取响应内容进行进一步验证
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			resultChan <- UnblockTestResult{movieID, false, err}
			return
		}

		bodyStr := string(body)

		// 检查是否包含地区限制的关键词
		// 如果包含这些关键词，说明虽然返回 200 但实际上是地区限制页面
		if strings.Contains(bodyStr, "Not Available") ||
			strings.Contains(bodyStr, "not available") ||
			strings.Contains(bodyStr, "geographic") ||
			strings.Contains(bodyStr, "isn't available") ||
			strings.Contains(bodyStr, "area") {
			resultChan <- UnblockTestResult{movieID, false, nil}
			return
		}

		// 检查是否包含正常页面的标志
		// 正常的 Netflix 影片页面会包含这些元素
		if strings.Contains(bodyStr, "watch-video") ||
			strings.Contains(bodyStr, "playback") ||
			strings.Contains(bodyStr, "\"availability\"") {
			resultChan <- UnblockTestResult{movieID, true, nil}
			return
		}
	}

	// 其他情况都视为不可用
	resultChan <- UnblockTestResult{movieID, false, nil}
}

// intToString 整数转字符串辅助函数
func intToString(n int) string {
	if n == 0 {
		return "0"
	}

	negative := false
	if n < 0 {
		negative = true
		n = -n
	}

	var result []byte
	for n > 0 {
		result = append([]byte{byte('0' + n%10)}, result...)
		n /= 10
	}

	if negative {
		result = append([]byte{'-'}, result...)
	}

	return string(result)
}
