package platform

import (
	"io"
	"net/http"
	"regexp"
	"strings"
)

func CheckNetflix(httpClient *http.Client) (bool, error) {
	// Test with LEGO Ninjago (title 81280792)
	result1, err1 := checkNetflixTitle(httpClient, "81280792")
	if err1 != nil {
		return false, err1
	}

	// Test with Breaking Bad (title 70143836)
	result2, err2 := checkNetflixTitle(httpClient, "70143836")
	if err2 != nil {
		return false, err2
	}

	// If both show "Oh no!" message, it's Originals Only
	if strings.Contains(result1, "Oh no!") && strings.Contains(result2, "Oh no!") {
		return false, nil
	}

	// If either one is accessible (no "Oh no!"), Netflix is unlocked
	if !strings.Contains(result1, "Oh no!") || !strings.Contains(result2, "Oh no!") {
		return true, nil
	}

	return false, nil
}

func checkNetflixTitle(httpClient *http.Client, titleID string) (string, error) {
	url := "https://www.netflix.com/title/" + titleID
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	// Set comprehensive headers to mimic browser behavior
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0")
	req.Header.Set("Sec-Ch-Ua", `"Microsoft Edge";v="135", "Not-A.Brand";v="8", "Chromium";v="135"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Priority", "u=0, i")

	// Set cookies to simulate authenticated session
	cookies := []string{
		"flwssn=d2c72c47-49e9-48da-b7a2-2dc6d7ca9fcf",
		"nfvdid=BQFmAAEBEMZa4XMYVzVGf9-kQ1HXumtAKsCyuBZU4QStC6CGEGIVznjNuuTerLAG8v2-9V_kYhg5uxTB5_yyrmqc02U5l1Ts74Qquezc9AE-LZKTo3kY3g%3D%3D",
		"SecureNetflixId=v%3D3%26mac%3DAQEAEQABABSQHKcR1d0sLV0WTu0lL-BO63TKCCHAkeY.%26dt%3D1745376277212",
		"NetflixId=v%3D3%26ct%3DBgjHlOvcAxLAAZuNS4_CJHy9NKJPzUV-9gElzTlTsmDS1B59TycR-fue7f6q7X9JQAOLttD7OnlldUtnYWXL7VUfu9q4pA0gruZKVIhScTYI1GKbyiEqKaULAXOt0PHQzgRLVTNVoXkxcbu7MYG4wm1870fZkd5qrDOEseZv2WIVk4xIeNL87EZh1vS3RZU3e-qWy2tSmfSNUC-FVDGwxbI6-hk3Zg2MbcWYd70-ghohcCSZp5WHAGXg_xWVC7FHM3aOUVTGwRCU1RgGIg4KDKGr_wsTRRw6HWKqeA..",
		"gsid=09bb180e-fbb1-4bf6-adcb-a3fa1236e323",
	}
	req.Header.Set("Cookie", strings.Join(cookies, "; "))

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// GetNetflixRegion extracts the region code from Netflix response
func GetNetflixRegion(body string) string {
	// Extract region using regex pattern: "id":"XX","countryName"
	re := regexp.MustCompile(`"id":"([^"]+)","countryName"`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
