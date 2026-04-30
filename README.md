# OrphanX
# Recon Bot
# ⚠️ Work in progress — not fully tested yet. Contributions welcome.
Automated subdomain takeover discovery pipeline triggered via Telegram. Send a domain and receive a full forensic report with evidence of potential subdomain takeovers.

## Features

- **Telegram-powered**: Trigger scans via Telegram bot commands
- **8-stage pipeline**: Comprehensive subdomain enumeration and takeover detection
- **Passive discovery**: Uses subfinder, assetfinder, and amass for subdomain enumeration
- **NXDOMAIN gating**: Mandatory verification before HTTP probing to reduce false positives
- **Cloud provider detection**: Identifies CNAMEs pointing to 40+ cloud providers
- **Nuclei integration**: Confirms takeovers using latest takeover templates
- **Evidence collection**: Automated dig + gowitness screenshot collection
- **Professional reports**: HTML dashboard + ZIP archive delivered via Telegram

## Architecture

```
Telegram Bot (python-telegram-bot v20+)
    ↓
Pipeline Orchestrator (asyncio)
    ↓
Stage 1: Passive Discovery  → subfinder + assetfinder + amass
Stage 2: DNS Resolution     → dnsx
Stage 3: CNAME Filtering    → grep + cname_whitelist.txt → cloud_watchlist
Stage 4: NXDOMAIN Gate      → nslookup per CNAME destination
Stage 5: HTTP Probing       → httpx
Stage 6: Confirmation       → nuclei (takeover templates)
Stage 7: Evidence           → dig + gowitness → Silos
Stage 8: Report             → HTML + zip → Telegram
```

## Bot Commands

| Command | Description |
|---------|-------------|
| `/scan example.com` | Run full pipeline |
| `/status` | Show current stage |
| `/watchlist example.com` | Re-scan cloud watchlist |
| `/report example.com` | Send latest report |
| `/cancel` | Stop current scan |

## Installation

### Prerequisites

- Python 3.8+
- Go 1.16+ (for security tools)
- Ubuntu/Linux (optimized for Azure)

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Install Security Tools

```bash
# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/projectdiscovery/dnsx@latest
go install -v github.com/projectdiscovery/httpx@latest
go install -v github.com/projectdiscovery/nuclei@latest
go install -v github.com/sensepost/gowitness@latest

# Install Amass
sudo apt install amass

# Install nuclei templates
nuclei -update-templates
```

### Environment Variables

```bash
export TELEGRAM_BOT_TOKEN="your_bot_token_here"

# Optional API keys
export GITHUB_TOKEN="your_github_token"
export VIRUSTOTAL_API_KEY="your_vt_key"
export ALIENVAULT_OTX_API_KEY="your_otx_key"
export CHAOS_API_KEY="your_chaos_key"
```

## Usage

### Start the Bot

```bash
python main.py
```

### Example Session

```
User: /scan example.com
Bot:  Starting scan for example.com...
Bot:  ✅ Found 150 subdomains
Bot:  🔍 23 cloud CNAMEs found
Bot:  ⚠️ 8 dangling confirmed
Bot:  🚨 CRITICAL: Takeover on api.example.com
Bot:  🚨 CRITICAL: Takeover on dev.example.com
Bot:  📦 Report ready (sends zip)
```

## Output Structure

```
targets/
└── example.com/
    ├── cloud_watchlist.txt         # Persistent cloud CNAME archive
    ├── example.com_subdomains.txt
    ├── example.com_resolved.txt
    ├── example.com_suspicious.txt
    ├── example.com_dangling.txt
    ├── example.com_probed.txt
    ├── example.com_nuclei.jsonl
    ├── evidence/
    │   ├── api.example.com/
    │   │   ├── api.example.com_dns.txt
    │   │   └── api.example.com.png
    │   └── dev.example.com/
    │       ├── dev.example.com_dns.txt
    │       └── dev.example.com.png
    └── example.com_Final_Report/
        ├── dashboard.html
        └── example.com_report.zip
```

## Pipeline Stages

### Stage 1: Passive Discovery
Runs subfinder, assetfinder, and amass concurrently to enumerate subdomains passively.

### Stage 2: DNS Resolution
Resolves subdomains using dnsx to capture A, AAAA, and CNAME records. NXDOMAIN responses are tracked as potential takeover candidates.

### Stage 3: CNAME Filtering
Filters resolved domains for CNAMEs pointing to cloud providers (AWS, Azure, GCP, Cloudflare, etc.). Suspicious entries are archived to `cloud_watchlist.txt`.

### Stage 4: NXDOMAIN Gate
**Mandatory gate** - Verifies CNAME targets with nslookup. NXDOMAIN on CNAME target = potential takeover (orphaned service).

### Stage 5: HTTP Probing
Probes dangling domains with httpx to detect:
- Cloud provider default pages
- 404 with zero content
- Redirects to registration pages
- Certificate mismatches

### Stage 6: Takeover Confirmation
Runs nuclei with takeover templates to confirm vulnerabilities. Templates are automatically updated before each scan.

### Stage 7: Evidence Collection
Collects evidence silos for confirmed findings:
- DNS records via dig
- Screenshots via gowitness

### Stage 8: Report Generation
Generates:
- HTML dashboard with statistics and charts
- ZIP archive with all evidence

## Key Rules

1. **Always use absolute tool paths** - Non-interactive shell ignores PATH
2. **Always pipe through anew** - Never use `>`
3. **Amass stderr → 2>/dev/null** - Suppress verbose output
4. **Nuclei templates must be updated before each scan** - Critical for detection accuracy
5. **Nslookup gate is mandatory** - No HTTP probing without NXDOMAIN confirmation
6. **Cloud watchlist is append-only** - Never overwrite existing entries

## Tool Reference

| Tool | Path | Purpose |
|------|------|---------|
| subfinder | `/home/azureuser/go/bin/subfinder` | Passive subdomain enumeration |
| assetfinder | `/home/azureuser/go/bin/assetfinder` | Passive subdomain enumeration |
| amass | `/usr/local/bin/amass` | Passive subdomain enumeration |
| anew | `/home/azureuser/go/bin/anew` | Deduplicated file append |
| dnsx | `/home/azureuser/go/bin/dnsx` | DNS resolution |
| httpx | `/home/azureuser/go/bin/httpx` | HTTP probing |
| nuclei | `/home/azureuser/go/bin/nuclei` | Takeover confirmation |
| gowitness | `/home/azureuser/go/bin/gowitness` | Screenshot capture |
| dig | (system) | DNS record collection |
| nslookup | (system) | NXDOMAIN verification |

## Project Structure

```
recon-bot/
├── main.py                 # Telegram bot entry point
├── config.py               # API keys, paths, settings
├── requirements.txt
├── pipeline/
│   ├── __init__.py         # Pipeline orchestrator
│   ├── stage1_discovery.py # Subfinder + Assetfinder + Amass
│   ├── stage2_dns.py       # DNSx resolution
│   ├── stage3_filter.py    # CNAME filtering + cloud watchlist
│   ├── stage4_nslookup.py  # NXDOMAIN verification
│   ├── stage5_httpx.py     # HTTP probing
│   ├── stage6_nuclei.py   # Nuclei takeover confirmation
│   ├── stage7_evidence.py  # Dig + Gowitness evidence collection
│   └── stage8_report.py    # HTML report + ZIP archive
├── utils/
│   ├── __init__.py
│   ├── notifier.py         # Telegram notifications
│   ├── file_manager.py     # Atomic writes, file locking
│   └── watchlist.py       # Cloud watchlist management
└── data/
    ├── cname_whitelist.txt # Cloud provider patterns
    └── resolvers.txt       # Trusted DNS resolvers
```

## Configuration

API keys are loaded from environment variables. See `config.py` for all supported options:

- `GITHUB_TOKEN` / `GITHUB_TOKEN_2` / `GITHUB_TOKEN_3`
- `VIRUSTOTAL_API_KEY`
- `ALIENVAULT_OTX_API_KEY`
- `CHAOS_API_KEY`
- `TELEGRAM_BOT_TOKEN`

## Periodic Watchlist Rescan

The `/watchlist` command re-runs Stage 4 on all cloud watchlist entries:
1. Reads `cloud_watchlist.txt`
2. Re-runs nslookup on all CNAME targets
3. New NXDOMAIN → enters Stage 5 immediately
4. Appends new findings to existing silos

## License

This tool is for **authorized security testing only**. Ensure you have explicit permission before scanning any domain.

## Disclaimer

The operators of this tool are not responsible for misuse or damage caused by this tool. Use responsibly and ethically.
