package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

var zoomEyeRequestConfig = requestConfig{
	RetryBaseDelay: 5 * time.Second,
}

type zoomEyeResponse struct {
	List []struct {
		Name string `json:"name"`
	} `json:"list"`
}

func FetchZoomEye(domain string) ([]string, error) {
	opts := currentOptions()
	if opts.ZoomEyeKey == "" {
		return nil, authRequiredSourceError("ZoomEye requires zoomeye_api_key to be configured", nil)
	}

	requestURL := fmt.Sprintf("https://api.zoomeye.hq/domain/search?q=%s&type=1&page=1", url.QueryEscape(domain))
	headers := map[string]string{"API-KEY": opts.ZoomEyeKey}

	body, err := fetchBody(requestURL, headers, "application/json", zoomEyeRequestConfig)
	if err != nil {
		return nil, classifyZoomEyeError(err)
	}

	results, err := parseZoomEyeResponse(body)
	if err != nil {
		return nil, degradedSourceError("ZoomEye returned invalid JSON", err)
	}

	return results, nil
}

func parseZoomEyeResponse(body []byte) ([]string, error) {
	var response zoomEyeResponse
	if err := decodeJSON(body, &response); err != nil {
		return nil, err
	}

	results := make([]string, 0, len(response.List))
	for _, entry := range response.List {
		if entry.Name != "" {
			results = append(results, entry.Name)
		}
	}

	return results, nil
}

func classifyZoomEyeError(err error) error {
	switch {
	case IsStatusCode(err, 429):
		return rateLimitedSourceError("ZoomEye is rate limiting requests", err)
	case IsStatusCode(err, 401), IsStatusCode(err, 403):
		return authRequiredSourceError("ZoomEye rejected the configured API key", err)
	default:
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return degradedSourceError("ZoomEye returned malformed JSON", err)
		}

		return degradedSourceError("ZoomEye request failed", err)
	}
}
