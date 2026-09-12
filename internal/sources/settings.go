package sources

import (
	"fmt"
	"os"
	"sync"
	"time"
)

type Options struct {
	Timeout      time.Duration
	Retries      int
	Verbose      bool
	OTXAPIKey    string
	VTAPIKey     string
	ShodanAPIKey string
	FofaEmail    string
	FofaKey      string
	ZoomEyeKey   string
}

const defaultTimeout = 30 * time.Second

var (
	optionsMu sync.RWMutex
	logMu     sync.Mutex
	settings  = Options{
		Timeout: defaultTimeout,
		Retries: 2,
	}
)

func Configure(options Options) {
	if options.Timeout <= 0 {
		options.Timeout = defaultTimeout
	}

	if options.Retries < 0 {
		options.Retries = 0
	}

	optionsMu.Lock()
	settings = options
	httpClient.Timeout = options.Timeout
	optionsMu.Unlock()
}

func currentOptions() Options {
	optionsMu.RLock()
	defer optionsMu.RUnlock()
	return settings
}

func verbosef(format string, args ...any) {
	if !currentOptions().Verbose {
		return
	}

	logMu.Lock()
	defer logMu.Unlock()
	fmt.Fprintf(os.Stderr, "[v] "+format+"\n", args...)
}

func OTXAPIKeyEnabled() bool {
	return currentOptions().OTXAPIKey != ""
}

func VirusTotalEnabled() bool {
	return currentOptions().VTAPIKey != ""
}

func ShodanEnabled() bool {
	return currentOptions().ShodanAPIKey != ""
}

func FofaEnabled() bool {
	opts := currentOptions()
	return opts.FofaEmail != "" && opts.FofaKey != ""
}

func ZoomEyeEnabled() bool {
	return currentOptions().ZoomEyeKey != ""
}
