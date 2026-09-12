package sources

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var fofaRequestConfig = requestConfig{
	RetryBaseDelay: 5 * time.Second,
}

type fofaRequestBody struct {
	QBase64 string `json:"qbase64"`
	Size    int    `json:"size"`
	Fields  string `json:"fields"`
	Email   string `json:"email"`
	Key     string `json:"key"`
}

type fofaResponse struct {
	Results [][]string `json:"results"`
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg"`
}

func FetchFofa(domain string) ([]string, error) {
	opts := currentOptions()
	if opts.FofaEmail == "" || opts.FofaKey == "" {
		return nil, authRequiredSourceError("FOFA requires fofa_email and fofa_key to be configured", nil)
	}

	query := fmt.Sprintf("domain==%s", domain)
	qbase64 := base64.StdEncoding.EncodeToString([]byte(query))

	reqBody := fofaRequestBody{
		QBase64: qbase64,
		Size:    100,
		Fields:  "host",
		Email:   opts.FofaEmail,
		Key:     opts.FofaKey,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, degradedSourceError("failed to encode FOFA request body", err)
	}

	body, err := fetchBodyPost("https://fofa.info/api/v1/search/all", bodyBytes, "application/json")
	if err != nil {
		return nil, classifyFofaError(err)
	}

	results, err := parseFofaResponse(body)
	if err != nil {
		return nil, degradedSourceError("FOFA returned invalid JSON", err)
	}

	return results, nil
}

func parseFofaResponse(body []byte) ([]string, error) {
	var response fofaResponse
	if err := decodeJSON(body, &response); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{}, len(response.Results))
	results := make([]string, 0, len(response.Results))

	for _, row := range response.Results {
		if len(row) == 0 {
			continue
		}

		host := strings.TrimSpace(row[0])
		// Strip port suffix (e.g. "sub.example.com:8080" → "sub.example.com").
		// net.SplitHostPort handles both host:port and [ipv6]:port forms.
		if stripped, _, err := net.SplitHostPort(host); err == nil {
			host = stripped
		}

		host = strings.ToLower(host)
		if host == "" {
			continue
		}

		if _, ok := seen[host]; ok {
			continue
		}

		seen[host] = struct{}{}
		results = append(results, host)
	}

	return results, nil
}

func classifyFofaError(err error) error {
	switch {
	case IsStatusCode(err, 401), IsStatusCode(err, 403):
		return authRequiredSourceError("FOFA rejected the configured API credentials", err)
	case IsStatusCode(err, 429):
		return rateLimitedSourceError("FOFA is rate limiting requests", err)
	default:
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return degradedSourceError("FOFA returned malformed JSON", err)
		}

		return degradedSourceError("FOFA request failed", err)
	}
}
