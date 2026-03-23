# Web Recon Automation Tool

A Python-based web reconnaissance automation toolkit for penetration testing and security assessments. The tool collects intelligence from multiple sources and generates a clean HTML report.

## Features

- Subdomain enumeration from crt.sh public certificate transparency API (no API key required)
- DNS brute force from a local wordlist using multithreading
- Port scanning with `python-nmap` (top 1000 ports + service version detection)
- Automatic nmap binary discovery in common system paths (no manual PATH edits required in most setups)
- Built-in threaded socket fallback scan if nmap is unavailable
- Technology fingerprinting with `builtwith`
- HTTP security header analysis for common hardening headers
- WHOIS lookup with `python-whois`
- Parallel module execution with `concurrent.futures`
- Auto-generated HTML and JSON reports

## Project Structure

```text
web-recon-tool/
├── recon.py
├── modules/
│   ├── __init__.py
│   ├── subdomain.py
│   ├── portscan.py
│   ├── techdetect.py
│   ├── headers.py
│   ├── whois_lookup.py
│   └── report_generator.py
├── wordlists/
│   └── subdomains.txt
├── reports/
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.9+
- `nmap` binary installed on the operating system (required by `python-nmap`)

### Install System Dependency (nmap)

Ubuntu/Debian:

```bash
sudo apt update && sudo apt install -y nmap
```

Fedora:

```bash
sudo dnf install -y nmap
```

macOS (Homebrew):

```bash
brew install nmap
```

## Installation

```bash
cd web_recon_tool
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
python recon.py -d example.com
```

With a custom wordlist:

```bash
python recon.py -d example.com -w wordlists/subdomains.txt -o reports/example_report.html
```

With a deeper port scan profile:

```bash
python recon.py -d example.com --scan-profile deep
```

## CLI Arguments

- `-d, --domain`: Target domain (required)
- `-o, --output`: Output HTML report path (optional)
- `-w, --wordlist`: Wordlist file path for DNS brute force (optional)
- `--scan-profile`: `fast` (default), `balanced`, or `deep`

Default output behavior:

- If `-o` is not provided, report is auto-saved as `reports/<target-domain>.html`

## What the Tool Checks

1. Subdomains from crt.sh
2. DNS brute-force discovered hostnames
3. Open ports, protocols, services, and versions
4. Security headers:
   - Content-Security-Policy
   - X-Frame-Options
   - Strict-Transport-Security
   - X-Content-Type-Options
   - Referrer-Policy
5. Web technology stack
6. WHOIS domain registration details

## Output Files

Running the command generates:

- HTML report at the path passed to `-o`
- JSON raw findings at the same filename with `.json` extension

If `-o` is omitted:

- HTML report: `reports/<target-domain>.html`
- JSON findings: `reports/<target-domain>.json`

Example:

- `reports/example_report.html`
- `reports/example_report.json`

## Sample Terminal Output

```text
[*] Running web recon for: example.com
[*] Port scan profile: fast
[*] Output report: reports/example.com.html
[*] This may take some time depending on network conditions and target response speed.

[+] Starting subdomain module...
[+] Starting portscan module...
[+] Starting techdetect module...
[+] Starting headers module...
[+] Starting whois_lookup module...
[+] Completed headers module in 0.5s
   [=] missing_headers=3 | X-Frame-Options, X-Content-Type-Options, Referrer-Policy
[+] Completed portscan module in 0.8s
   [=] open_ports=2 | scanner=socket-fallback | ports: 80, 443
[+] Completed subdomain module in 14.2s
   [=] subdomains=18 | crt.sh=15 | dns_bruteforce=3 | sample: api.example.com, dev.example.com
[+] Completed techdetect module in 1.2s
   [=] tech_categories=4 | categories: web-servers, javascript-frameworks
[+] Completed whois_lookup module in 1.8s
   [=] whois_fields=14 | registrar: Example Registrar

[+] Recon completed
[+] HTML report saved to: reports/example_report.html
[+] JSON findings saved to: reports/example.com.json
```

## Report Sections

The HTML report includes:

- Subdomains table
- Open ports table
- Security headers table (missing headers highlighted in red)
- Technology stack table
- WHOIS information table

## Notes and Limitations

- Some modules may partially fail depending on target behavior, DNS setup, firewalls, or rate limits.
- The tool continues execution and captures errors per module instead of exiting early.
- Port scanning can take time on slower networks, especially with `--scan-profile deep`.
- If nmap is not installed, the tool automatically uses a faster socket fallback over common ports (without advanced service/version fingerprint depth).

## Legal Disclaimer

Use this tool only on systems and domains you own or are explicitly authorized to test. Unauthorized scanning or reconnaissance may violate laws and regulations.
