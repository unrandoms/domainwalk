package main

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lumiaurora/subscan/internal/output"
	"github.com/lumiaurora/subscan/internal/sources"
)

func TestSelectSourcesIncludeExclude(t *testing.T) {
	registry := []sourceDefinition{
		{id: "alpha", name: "Alpha", aliases: []string{"alpha"}},
		{id: "beta", name: "Beta", aliases: []string{"beta"}},
		{id: "gamma", name: "Gamma", aliases: []string{"gamma"}, enabled: func() bool { return false }, enableHint: "missing key"},
	}

	selected, err := selectSources(registry, []string{"alpha", "beta"}, []string{"beta"})
	if err != nil {
		t.Fatalf("selectSources returned error: %v", err)
	}

	if len(selected) != 1 || selected[0].id != "alpha" {
		t.Fatalf("expected only alpha to remain after exclusion")
	}

	if _, err := selectSources(registry, []string{"gamma"}, nil); err == nil {
		t.Fatalf("expected disabled source selection to fail")
	}
}

func TestParseCSVListDeduplicates(t *testing.T) {
	got := parseCSVList("crtsh, certspotter,crtsh,  urlscan ")
	want := []string{"crtsh", "certspotter", "urlscan"}

	if len(got) != len(want) {
		t.Fatalf("expected %d values, got %d", len(want), len(got))
	}

	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("entry %d: want %q, got %q", index, want[index], got[index])
		}
	}
}

func TestAggregateSourceEntriesTracksAttribution(t *testing.T) {
	results := []sourceResult{
		{
			source:  sourceDefinition{name: "crt.sh"},
			entries: []string{"WWW.example.com", "*.api.example.com", "invalid.org"},
		},
		{
			source:  sourceDefinition{name: "Cert Spotter"},
			entries: []string{"api.example.com", "mail.example.com", "mail.example.com"},
		},
		{
			source: sourceDefinition{name: "AlienVault OTX"},
			err:    errSentinel{},
		},
	}

	rawCount, unique, attribution := aggregateSourceEntries("example.com", results)
	if rawCount != 6 {
		t.Fatalf("expected raw count 6, got %d", rawCount)
	}

	wantUnique := []string{"api.example.com", "mail.example.com", "www.example.com"}
	if !slices.Equal(unique, wantUnique) {
		t.Fatalf("expected unique %v, got %v", wantUnique, unique)
	}

	if !slices.Equal(attribution["api.example.com"], []string{"Cert Spotter", "crt.sh"}) {
		t.Fatalf("unexpected attribution for api.example.com: %v", attribution["api.example.com"])
	}
}

func TestParseTargetLinesSkipsCommentsAndDeduplicates(t *testing.T) {
	input := strings.NewReader("\n# comment\nExample.com\nexample.com\nsecond.example\n")
	got, err := parseTargetLines(input)
	if err != nil {
		t.Fatalf("parseTargetLines returned error: %v", err)
	}

	want := []string{"Example.com", "second.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestPrepareTargetsSeparatesInvalidDomains(t *testing.T) {
	targets, invalid := prepareTargets([]string{"Example.com", "bad domain", "example.com", "*.api.example.com"})
	if !slices.Equal(targets, []string{"example.com", "api.example.com"}) {
		t.Fatalf("unexpected prepared targets: %v", targets)
	}

	if len(invalid) != 1 || invalid[0].Domain != "bad domain" {
		t.Fatalf("unexpected invalid targets: %v", invalid)
	}
}

func TestBuildBatchReportCountsTargets(t *testing.T) {
	startedAt := time.Unix(100, 0).UTC()
	completedAt := startedAt.Add(2 * time.Second)
	report := buildBatchReport([]output.Report{{Domain: "example.com"}}, []output.TargetFailure{{Domain: "bad", Error: "invalid domain"}}, true, startedAt, completedAt)

	if report.TotalTargets != 2 {
		t.Fatalf("expected total targets 2, got %d", report.TotalTargets)
	}

	if report.Metadata.SuccessfulTargets != 1 || report.Metadata.FailedTargets != 1 {
		t.Fatalf("unexpected batch metadata: %+v", report.Metadata)
	}

	if !report.ResolvedEnabled {
		t.Fatalf("expected resolved flag to be true")
	}
}

func TestFetchWithRateLimitRetrySucceedsAfterRateLimit(t *testing.T) {
	// Override delays so the test does not actually sleep.
	origBase, origJitter := rateLimitBaseDelay, rateLimitJitterRange
	rateLimitBaseDelay, rateLimitJitterRange = 0, 0
	t.Cleanup(func() { rateLimitBaseDelay, rateLimitJitterRange = origBase, origJitter })

	calls := 0
	src := sourceDefinition{
		name: "TestSource",
		fetch: func(_ string) ([]string, error) {
			calls++
			if calls < 2 {
				return nil, &sources.SourceError{Health: sources.HealthRateLimited, Message: "rate limited"}
			}
			return []string{"sub.example.com"}, nil
		},
	}

	entries, err := fetchWithRateLimitRetry(src, "example.com", false)
	if err != nil {
		t.Fatalf("expected success after retry, got error: %v", err)
	}

	if len(entries) != 1 || entries[0] != "sub.example.com" {
		t.Fatalf("unexpected entries: %v", entries)
	}

	if calls != 2 {
		t.Fatalf("expected 2 calls (1 rate-limited + 1 success), got %d", calls)
	}
}

func TestFetchWithRateLimitRetryExhaustsMaxRetries(t *testing.T) {
	origBase, origJitter := rateLimitBaseDelay, rateLimitJitterRange
	rateLimitBaseDelay, rateLimitJitterRange = 0, 0
	t.Cleanup(func() { rateLimitBaseDelay, rateLimitJitterRange = origBase, origJitter })

	calls := 0
	src := sourceDefinition{
		name: "TestSource",
		fetch: func(_ string) ([]string, error) {
			calls++
			return nil, &sources.SourceError{Health: sources.HealthRateLimited, Message: "always rate limited"}
		},
	}

	_, err := fetchWithRateLimitRetry(src, "example.com", false)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}

	if sources.ErrorHealth(err) != sources.HealthRateLimited {
		t.Fatalf("expected rate-limited health after exhausted retries, got %s", sources.ErrorHealth(err))
	}

	// 1 initial attempt + maxRateLimitRetries retries
	if calls != maxRateLimitRetries+1 {
		t.Fatalf("expected %d calls, got %d", maxRateLimitRetries+1, calls)
	}
}

func TestFetchWithRateLimitRetryNoRetryOnOtherErrors(t *testing.T) {
	calls := 0
	src := sourceDefinition{
		name: "TestSource",
		fetch: func(_ string) ([]string, error) {
			calls++
			return nil, &sources.SourceError{Health: sources.HealthDegraded, Message: "degraded"}
		},
	}

	_, err := fetchWithRateLimitRetry(src, "example.com", false)
	if err == nil {
		t.Fatal("expected error")
	}

	if calls != 1 {
		t.Fatalf("expected exactly 1 call for non-rate-limited error, got %d", calls)
	}
}

type errSentinel struct{}

func (errSentinel) Error() string {
	return "boom"
}
