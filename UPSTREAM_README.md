# subscan

[![CI](https://github.com/lumiaurora/subscan/actions/workflows/ci.yml/badge.svg)](https://github.com/lumiaurora/subscan/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lumiaurora/subscan)](https://github.com/lumiaurora/subscan/releases)
[![License](https://img.shields.io/github/license/lumiaurora/subscan)](LICENSE)

`subscan` is a passive subdomain enumeration CLI written in Go for security research, OSINT portfolio work, and learning. It collects subdomains from multiple public passive sources, cleans the results, optionally resolves DNS, and exports findings in JSON or TXT.

## Why passive enumeration matters

Passive enumeration helps map an organization's external surface area without sending aggressive traffic to the target. It is useful for:

- security reconnaissance and asset discovery
- OSINT investigations
- lab practice and portfolio projects
- validating known infrastructure from public data sources

Because it relies on third-party public datasets, it is safer and quieter than active techniques, but it should still be used responsibly.

## Features

- passive-only by design with no brute force or active probing
- concurrent collection from multiple public sources
- built-in support for `crt.sh`, `AlienVault OTX`, `BufferOver`, `Cert Spotter`, `HackerTarget`, `Anubis`, `urlscan`, and `RapidDNS`
- optional `VirusTotal` and `Shodan` support via API keys
- batch input support from files or stdin
- per-run source selection with `--source` and `--exclude-source`
- configurable concurrency, timeout, retries, and verbose logging
- config file support for API keys and default runtime settings
- source health reporting with `enabled`, `disabled`, `degraded`, `auth-required`, and `rate-limited` states
- fixture-backed parser tests for every passive source
- CI coverage for `go test`, `go test -race`, Goreleaser config validation, and opt-in live integration tests
- normalization, wildcard cleanup, domain filtering, and deduplication
- optional concurrent DNS resolution checks with wildcard DNS filtering when `--resolve` is enabled
- rich JSON reports with timestamps, source attribution, source timings, and DNS details
- export to JSON or TXT
- clean terminal output with source progress and summary counts
- resilient error handling so one source failure does not stop the run
- cross-platform Go CLI for macOS, Linux, and Windows

## Project structure

```text
subscan/
  .goreleaser.yaml
  CHANGELOG.md
  LICENSE
  config.example.json
  main.go
  go.mod
  README.md
  internal/
    buildinfo/
      buildinfo.go
    config/
      config.go
    sources/
      anubis.go
      bufferover.go
      certspotter.go
      client.go
      crtsh.go
      hackertarget.go
      otx.go
      rapiddns.go
      settings.go
      shodan.go
      urlscan.go
      virustotal.go
    resolver/
      resolver.go
    output/
      output.go
    utils/
      clean.go
      filter.go
```

## Installation

Download the latest release archive from [GitHub Releases](https://github.com/lumiaurora/subscan/releases), then verify it with the published `checksums.txt` file.

Install with Homebrew:

```bash
brew tap lumiaurora/tap
brew install --cask subscan
```

Install with Scoop:

```powershell
scoop bucket add lumiaurora https://github.com/lumiaurora/scoop-bucket
scoop install subscan
```

Build from source locally:

Clone the repository and build it locally:

```bash
git clone https://github.com/lumiaurora/subscan.git
cd subscan
go build -o subscan .
```

On Windows:

```powershell
go build -o subscan.exe .
```

## Build instructions

Build the binary:

```bash
go build .
```

Build all packages:

```bash
go build ./...
```

Run directly without creating a binary:

```bash
go run . -d example.com
```

Print build information:

```bash
go run . --version
```

## Usage

```text
subscan -d example.com [--resolve] [--json|--txt] [--output file] [--source list] [--exclude-source list]
subscan --input domains.txt [--resolve] [--json|--txt] [--output file]
cat domains.txt | subscan --json --output results.json
subscan --version
```

`subscan` supports three configuration layers:

- CLI flags for per-run behavior
- environment variables for API keys
- an optional JSON config file for API keys and default settings

Precedence rules:

- CLI flags override config file defaults
- environment variables override API keys from the config file

### Flags

- `-d, --domain string`: target domain
- `-i, --input string`: read target domains from a file or `-` for stdin
- `--resolve`: resolve discovered hostnames and keep only live results
- `--json`: export results as JSON
- `--txt`: export results as TXT
- `--output string`: output file path
- `--source string`: comma-separated source IDs to include
- `--exclude-source string`: comma-separated source IDs to skip
- `--threads int`: max concurrent source requests and DNS workers
- `--timeout int`: HTTP and DNS timeout in seconds
- `--retries int`: retry count for passive source requests
- `--verbose`: show verbose runtime details
- `--version`: print version and build metadata
- `--config string`: optional config file path
- `--sources`: print the passive sources used by the tool

### Source IDs

Use these values with `--source` and `--exclude-source`:

- `crtsh`
- `otx`
- `bufferover`
- `certspotter`
- `hackertarget`
- `anubis`
- `urlscan`
- `rapiddns`
- `virustotal` (optional, requires API key)
- `shodan` (optional, requires API key)

### API keys

- `OTX_API_KEY`: helps reduce rate limiting from AlienVault OTX
- `VT_API_KEY`: enables VirusTotal subdomain collection
- `SHODAN_API_KEY`: enables Shodan DNS subdomain collection

### Default source behavior

By default, `subscan` enables these passive sources:

- `crt.sh`
- `AlienVault OTX`
- `BufferOver`
- `Cert Spotter`
- `HackerTarget`
- `Anubis`
- `urlscan`
- `RapidDNS`

`VirusTotal` and `Shodan` are optional and are only enabled when their API keys are configured.

`AlienVault OTX` runs without an API key, but public access may be rate limited. Setting `OTX_API_KEY` improves reliability.

You can inspect the currently enabled source set at runtime with:

```bash
subscan --sources
```

`--sources` now prints source health information so optional providers show up clearly as `enabled` or `disabled` before a run starts.

During enumeration, failed providers are reported with explicit runtime health states such as `rate-limited`, `auth-required`, or `degraded` instead of a generic failure message.

### Config file

Default config file path:

- macOS and Linux: `~/.config/subscan/config.json`
- Windows: `%AppData%\subscan\config.json`

You can also pass a custom path with `--config`.

An example file is included at `config.example.json`.

Example:

```json
{
  "otx_api_key": "",
  "vt_api_key": "",
  "shodan_api_key": "",
  "defaults": {
    "resolve": false,
    "json": false,
    "txt": false,
    "output": "",
    "threads": 20,
    "timeout_seconds": 30,
    "retries": 2,
    "verbose": false,
    "include_sources": ["crtsh", "certspotter", "rapiddns"],
    "exclude_sources": ["bufferover"]
  }
}
```

### API key examples

macOS and Linux:

```bash
export OTX_API_KEY=your_otx_key
export VT_API_KEY=your_virustotal_key
export SHODAN_API_KEY=your_shodan_key
subscan --sources
```

Windows PowerShell:

```powershell
$env:OTX_API_KEY="your_otx_key"
$env:VT_API_KEY="your_virustotal_key"
$env:SHODAN_API_KEY="your_shodan_key"
subscan.exe --sources
```

## Examples

Basic passive enumeration:

```bash
subscan -d example.com
```

Batch enumeration from a file:

```bash
subscan --input domains.txt --resolve --json --output results.json
```

Batch enumeration from stdin:

```bash
cat domains.txt | subscan --txt --output results.txt
```

Use only a specific source set:

```bash
subscan -d example.com --source crtsh,certspotter,urlscan
```

Exclude a flaky source for one run:

```bash
subscan -d example.com --exclude-source bufferover
```

Resolve discovered hostnames:

```bash
subscan -d example.com --resolve
```

Write JSON output:

```bash
subscan -d example.com --resolve --json --output results.json
```

Write TXT output:

```bash
subscan -d example.com --txt --output results.txt
```

Tune runtime behavior:

```bash
subscan -d example.com --threads 10 --timeout 20 --retries 1 --verbose
```

Use a custom config file:

```bash
subscan --config ./config.example.json --sources
```

Show the configured passive sources:

```bash
subscan --sources
subscan -d example.com --sources
```

Print version/build metadata:

```bash
subscan --version
```

## Sample output

```text
$ subscan -d example.com --resolve --json --output results.json
[+] Target: example.com
[+] Querying crt.sh...
[+] Querying AlienVault OTX...
[!] AlienVault OTX [rate-limited]: AlienVault OTX is rate limiting anonymous requests; set OTX_API_KEY to improve reliability
[+] Querying Cert Spotter...
[+] Querying RapidDNS...
[+] Querying urlscan...
[+] RapidDNS returned 23 candidate(s)
[+] Cert Spotter returned 27 candidate(s)
[+] urlscan returned 12 candidate(s)
[+] crt.sh returned 21 candidate(s)
[+] Raw results: 83
[+] Unique subdomains: 19
[+] Resolving discovered hosts...
[+] Wildcard-filtered subdomains: 2
[+] Live subdomains: 11
[+] Results written to results.json

api.example.com
cdn.example.com
dev.example.com
mail.example.com
vpn.example.com
```

## JSON output format

```json
{
  "domain": "example.com",
  "timestamp": "2026-04-20T10:15:04Z",
  "total_found": 11,
  "resolved_enabled": true,
  "metadata": {
    "started_at": "2026-04-20T10:15:01Z",
    "completed_at": "2026-04-20T10:15:04Z",
    "duration_ms": 2145,
    "raw_results": 83,
    "unique_subdomains": 19,
    "final_subdomains": 11,
    "wildcard_filtered": 2,
    "enabled_sources": [
      {
        "id": "crtsh",
        "name": "crt.sh"
      },
      {
        "id": "certspotter",
        "name": "Cert Spotter"
      }
    ],
    "failed_sources": [
      {
        "id": "otx",
        "name": "AlienVault OTX",
        "health": "rate-limited",
        "error": "AlienVault OTX is rate limiting anonymous requests; set OTX_API_KEY to improve reliability",
        "duration_ms": 801
      }
    ],
    "source_timings": [
      {
        "id": "crtsh",
        "name": "crt.sh",
        "status": "success",
        "candidates": 21,
        "duration_ms": 632
      },
      {
        "id": "otx",
        "name": "AlienVault OTX",
        "status": "rate-limited",
        "candidates": 0,
        "duration_ms": 801
      }
    ]
  },
  "subdomains": [
    {
      "name": "api.example.com",
      "sources": [
        "crt.sh",
        "Cert Spotter"
      ],
      "ips": [
        "93.184.216.34"
      ],
      "cnames": [
        "edge.example.net"
      ]
    },
    {
      "name": "cdn.example.com",
      "sources": [
        "RapidDNS",
        "urlscan"
      ]
    }
  ]
}
```

For multi-target runs, JSON output is wrapped in a batch report:

```json
{
  "timestamp": "2026-04-20T10:45:00Z",
  "total_targets": 2,
  "resolved_enabled": true,
  "metadata": {
    "started_at": "2026-04-20T10:44:55Z",
    "completed_at": "2026-04-20T10:45:00Z",
    "duration_ms": 5000,
    "successful_targets": 1,
    "failed_targets": 1
  },
  "results": [
    {
      "domain": "example.com",
      "timestamp": "2026-04-20T10:44:58Z",
      "total_found": 3,
      "resolved_enabled": true,
      "metadata": {
        "started_at": "2026-04-20T10:44:55Z",
        "completed_at": "2026-04-20T10:44:58Z",
        "duration_ms": 3000,
        "raw_results": 12,
        "unique_subdomains": 5,
        "final_subdomains": 3,
        "enabled_sources": [],
        "source_timings": []
      },
      "subdomains": []
    }
  ],
  "failed_targets": [
    {
      "domain": "bad target",
      "error": "invalid domain"
    }
  ]
}
```

For multi-target TXT output, each line uses `domain,subdomain` format.

## Source coverage notes

`subscan` uses public passive sources that can change, rate limit, retire, or return incomplete data over time. The tool is designed to continue running when one source fails, but enumeration quality depends on the availability and freshness of those public datasets.

Some providers are best-effort only. For example, public OTX access may return `429 Too Many Requests`, and BufferOver has been intermittently unavailable from some networks. `subscan` classifies those runtime failures as `rate-limited`, `auth-required`, or `degraded`, and every parser is covered by a local fixture test so upstream response format changes are easier to catch during development.

## Architecture

- `main.go`: CLI parsing, config loading, source selection, orchestration, and terminal UX
- `internal/config`: JSON config file loading and default config path handling
- `internal/buildinfo`: embedded version, commit, build date, and builder metadata
- `internal/sources`: passive source clients, source-specific parsing, health classification, retries/backoff, API key handling, and verbose request diagnostics
- `internal/utils`: normalization, wildcard cleanup, filtering, and deduplication
- `internal/resolver`: concurrent DNS resolution with configurable worker and timeout settings plus wildcard DNS detection
- `internal/output`: TXT and JSON exporters

## Release automation

Releases are built with Goreleaser.

- tagged releases publish cross-platform archives
- `checksums.txt` is attached to each release
- `checksums.txt.sigstore.json` is attached as a keyless Sigstore signature bundle for the checksums file
- SBOM files are generated for release archives
- binaries include embedded version, commit, build date, and builder metadata
- GitHub build provenance attestations are published for release artifacts
- Homebrew casks are published to `lumiaurora/homebrew-tap`
- Scoop manifests are published to `lumiaurora/scoop-bucket`

### Verifying signed checksums

Install `cosign`, then verify the published bundle against `checksums.txt`:

```bash
cosign verify-blob --bundle checksums.txt.sigstore.json checksums.txt
```

### Verifying provenance attestations

Use the GitHub CLI to verify release provenance:

```bash
gh attestation verify --repo lumiaurora/subscan subscan_1.0.2_linux_amd64.tar.gz
```

### macOS signing and notarization

The release pipeline is ready to sign and notarize macOS binaries when these GitHub Actions secrets are configured:

- `MACOS_SIGN_P12`
- `MACOS_SIGN_PASSWORD`
- `MACOS_NOTARY_KEY`
- `MACOS_NOTARY_KEY_ID`
- `MACOS_NOTARY_ISSUER_ID`

Until those secrets are set, Homebrew releases still include the quarantine-removal workaround for unsigned binaries.

## Testing

Run the standard test suite:

```bash
go test ./...
```

Run the race detector:

```bash
go test -race ./...
```

Run live integration tests manually:

```bash
SUBSCAN_RUN_LIVE_TESTS=1 SUBSCAN_LIVE_DOMAIN=cloudflare.com go test -tags=integration ./...
```

GitHub Actions also includes a manual `Integration` workflow for live passive-source checks.

## Disclaimer

`subscan` is for passive enumeration, authorized security research, OSINT, and learning purposes. Do not use it to violate laws, terms of service, or organizational policies. Always obtain permission where required.
