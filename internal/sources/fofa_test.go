package sources

import (
	"slices"
	"testing"
)

func TestParseFofaResponse(t *testing.T) {
	body := fixtureBytes(t, "fofa.json")
	got, err := parseFofaResponse(body)
	if err != nil {
		t.Fatalf("parseFofaResponse returned error: %v", err)
	}

	// fixture contains four rows; the duplicate "www.example.com" must be collapsed.
	want := []string{"www.example.com", "api.example.com", "mail.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestParseFofaResponsePortStripping(t *testing.T) {
	body := []byte(`{"results":[["sub.example.com:8080"],["api.example.com:443"]]}`)
	got, err := parseFofaResponse(body)
	if err != nil {
		t.Fatalf("parseFofaResponse returned error: %v", err)
	}

	want := []string{"sub.example.com", "api.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestParseFofaResponseEmpty(t *testing.T) {
	body := []byte(`{"results":[],"error":false}`)
	got, err := parseFofaResponse(body)
	if err != nil {
		t.Fatalf("parseFofaResponse returned error: %v", err)
	}

	if len(got) != 0 {
		t.Fatalf("expected empty results, got %v", got)
	}
}

func TestFofaAuthRequired(t *testing.T) {
	Configure(Options{Timeout: defaultTimeout})
	_, err := FetchFofa("example.com")
	if err == nil {
		t.Fatal("expected auth-required error when keys are empty")
	}

	if health := ErrorHealth(err); health != HealthAuthRequired {
		t.Fatalf("expected auth-required health, got %s", health)
	}
}

func TestParseZoomEyeResponse(t *testing.T) {
	body := fixtureBytes(t, "zoomeye.json")
	got, err := parseZoomEyeResponse(body)
	if err != nil {
		t.Fatalf("parseZoomEyeResponse returned error: %v", err)
	}

	want := []string{"www.example.com", "api.example.com", "mail.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestParseZoomEyeResponseEmpty(t *testing.T) {
	body := []byte(`{"list":[]}`)
	got, err := parseZoomEyeResponse(body)
	if err != nil {
		t.Fatalf("parseZoomEyeResponse returned error: %v", err)
	}

	if len(got) != 0 {
		t.Fatalf("expected empty results, got %v", got)
	}
}

func TestZoomEyeAuthRequired(t *testing.T) {
	Configure(Options{Timeout: defaultTimeout})
	_, err := FetchZoomEye("example.com")
	if err == nil {
		t.Fatal("expected auth-required error when key is empty")
	}

	if health := ErrorHealth(err); health != HealthAuthRequired {
		t.Fatalf("expected auth-required health, got %s", health)
	}
}
