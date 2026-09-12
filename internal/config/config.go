package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type File struct {
	OTXAPIKey    string   `json:"otx_api_key"`
	VTAPIKey     string   `json:"vt_api_key"`
	ShodanAPIKey string   `json:"shodan_api_key"`
	FofaEmail    string   `json:"fofa_email"`
	FofaKey      string   `json:"fofa_key"`
	ZoomEyeKey   string   `json:"zoomeye_api_key"`
	Defaults     Defaults `json:"defaults"`
}

type Defaults struct {
	Resolve        *bool    `json:"resolve"`
	JSON           *bool    `json:"json"`
	TXT            *bool    `json:"txt"`
	Output         string   `json:"output"`
	Threads        *int     `json:"threads"`
	TimeoutSeconds *int     `json:"timeout_seconds"`
	Retries        *int     `json:"retries"`
	Verbose        *bool    `json:"verbose"`
	IncludeSources []string `json:"include_sources"`
	ExcludeSources []string `json:"exclude_sources"`
}

func Load(path string, explicit bool) (File, string, error) {
	if path == "" {
		defaultPath, err := DefaultPath()
		if err != nil {
			return File{}, "", err
		}
		path = defaultPath
	}

	expandedPath, err := expandPath(path)
	if err != nil {
		return File{}, "", err
	}

	data, err := os.ReadFile(expandedPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			return File{}, "", nil
		}

		return File{}, "", err
	}

	var file File
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return File{}, "", err
	}

	return file, expandedPath, nil
}

func DefaultPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(configDir, "subscan", "config.json"), nil
}

func expandPath(path string) (string, error) {
	if path == "" || path[0] != '~' {
		return path, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	if path == "~" {
		return homeDir, nil
	}

	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		return filepath.Join(homeDir, path[2:]), nil
	}

	return path, nil
}
