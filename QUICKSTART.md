# BladeRecon Quickstart

This is the five-minute path from install to first report.

## 1. Install

```bash
git clone https://github.com/mohamedxk9tb/BladeRecon.git
cd BladeRecon
python -m venv .venv
```

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
```

Linux/macOS:

```bash
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

## 2. Verify

```bash
bladerecon --help
bladerecon doctor
```

Optional dependencies may show warnings. That is acceptable for a first scan.

## 3. Run First Scan

```bash
bladerecon subdomain hackerone.com
bladerecon probe hackerone.com
bladerecon js hackerone.com
bladerecon endpoints hackerone.com
bladerecon secrets hackerone.com
bladerecon param hackerone.com
bladerecon intelligence hackerone.com
bladerecon advanced hackerone.com --profile safe
```

Or run the standard workflow:

```bash
bladerecon full hackerone.com
```

For bug bounty targets, prefer the conservative safety profile:

```bash
bladerecon full hackerone.com --profile safe
```

## 4. Generate Report

```bash
bladerecon report hackerone.com
```

Reports are saved to:

```text
results/hackerone.com/reports/report.html
results/hackerone.com/reports/report.md
```

## 5. Open Report

Open:

```text
results/hackerone.com/reports/report.html
```

The report is offline and includes:

- Active safety profile
- A **Where Should I Start?** dashboard with the next targets to investigate
- Separate Research Opportunity Score and Program Risk Score
- Attack-surface summary
- Performance Analytics
- Subdomains
- Alive hosts
- JavaScript files
- Endpoints
- Parameters
- Recon intelligence
- Historical URLs, focused content discovery, header-derived assets, and priority assets with ranking reasons
- Secret pattern findings
- Screenshots if available
- Nuclei findings if available, including Smart Nuclei baseline safety-net status

Start with **Where Should I Start?** before reading inventory sections. It shows
why a target matters, what to test first, and the strongest supporting signals.

The README showcase images live under `assets/` and use sanitized `example.com`
data only.

## Useful Follow-Up Commands

```bash
bladerecon cache info
bladerecon resume hackerone.com
bladerecon --version
```

Install optional screenshot support:

```bash
python -m playwright install chromium
```

Install optional Nuclei support:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Nuclei can also be run with explicit safety and timeout controls:

```bash
bladerecon nuclei hackerone.com --profile safe --timeout 900
```
