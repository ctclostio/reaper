# Reaper

AI-powered black-box penetration testing tool. Autonomously discovers and exploits web application vulnerabilities using a 4-phase methodology mapped to the OWASP Top 10.

## How It Works

Reaper uses an AI agent backed by an MCP (Model Context Protocol) server that provides specialized pentesting tools. The agent reasons about the target, decides what to test, executes attacks, and reports only confirmed vulnerabilities with proof.

```
AI Agent → MCP Server → HTTP requests → Target
```

**4 Phases:**

1. **Reconnaissance** — Crawl and map the attack surface (endpoints, forms, tech stack, headers, cookies, TLS, CORS)
2. **Analysis** — Identify potential vulnerabilities across all OWASP Top 10 categories and plan exploitation
3. **Exploitation** — Execute attacks with curated payloads, confirm vulnerabilities with evidence
4. **Reporting** — Generate a markdown report with findings, reproduction steps, and remediation advice

## Requirements

- Python 3.10+
- [AI CLI](https://www.npmjs.com/package/@anthropic-ai/claude-code) installed and authenticated
- `pip install -r requirements.txt`

## Usage

```bash
python -m reaper <target-url> [options]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--scope` | target domain | Allowed URL prefixes (space-separated) |
| `--max-requests` | 500 | Maximum HTTP requests |
| `--timeout` | 10 | Request timeout in seconds |
| `--output` | `./reports` | Output directory for reports |
| `--model` | `claude-sonnet-4-5-20250929` | AI model to use |

### Examples

```bash
# Basic scan
python -m reaper http://localhost:3000

# Scan with higher request budget
python -m reaper http://target.com --max-requests 500

# Restrict scope to specific paths
python -m reaper http://target.com --scope http://target.com/api http://target.com/app
```

## MCP Tools

The MCP server exposes 11 pentesting tools:

| Tool | Description |
|------|-------------|
| `http_request` | Make HTTP requests with custom methods/headers/body |
| `crawl_page` | Extract links, forms, scripts, meta tags, comments |
| `check_headers` | Analyze security headers (CSP, HSTS, X-Frame-Options) |
| `check_cookies` | Check cookie security flags (Secure, HttpOnly, SameSite) |
| `check_cors` | Test CORS configuration with various origins |
| `check_methods` | Test for dangerous HTTP methods (TRACE, PUT, DELETE) |
| `check_tls` | Inspect TLS/SSL configuration and certificates |
| `test_payload` | Inject a payload into a specific parameter |
| `fuzz_parameter` | Batch-test multiple payloads against a parameter |
| `load_payloads` | Load curated payload lists (sqli, xss, ssti, traversal, ssrf) |
| `record_finding` | Record a confirmed vulnerability with evidence |

## Sample Output

```
Reaper Security Scan
Target: http://localhost:3000
Scope: ['http://localhost:3000']

============================================================
  PHASE: RECON
============================================================
  ...

============================================================
  SCAN COMPLETE
  Duration: 1538s
  Requests made: 129
  Findings: 3
============================================================

Findings Summary:
  [CRITICAL] SQL Injection in Product Search
  [CRITICAL] SQL Injection Authentication Bypass - Admin Account Compromise
  [MEDIUM] Verbose Error Messages with Stack Traces
```

## Report Format

Reports are saved as markdown with:

- Executive summary with severity counts
- Each finding includes: OWASP category, evidence, curl reproduction steps, remediation advice
- Attack surface summary
- Methodology section

## Disclaimer

**Only scan applications you own or have explicit authorization to test.** Unauthorized penetration testing is illegal. This tool is intended for security professionals, CTF participants, and authorized security assessments.

## License

MIT
