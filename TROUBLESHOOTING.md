# BladeRecon Troubleshooting

Start with:

```bash
bladerecon doctor
```

Doctor checks optional dependencies and write permissions.

## Chromium Missing

Symptoms:

```text
[SKIP] Screenshot module skipped
Reason: Chromium browser not installed
```

Fix:

```bash
python -m playwright install chromium
bladerecon doctor
```

Screenshots are optional. Full scans continue when Chromium is missing.

## Nuclei Missing

Symptoms:

```text
[SKIP] Nuclei module skipped
Reason: nuclei binary not found in PATH
```

Fix:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -version
bladerecon doctor
```

Ensure Go bin is in PATH.

The first install may look slow because Go downloads and compiles many dependencies. `bladerecon install-deps` prints progress and heartbeat messages during this stage.

## Nuclei Templates Missing

Symptoms:

```text
Nuclei templates missing; updating templates and retrying once
nuclei failed: templates unavailable at <home>/nuclei-templates
```

Fix:

```bash
bladerecon repair
bladerecon nuclei example.com
```

Manual template refresh:

```bash
nuclei -update-templates -update-template-dir ~/nuclei-templates
bladerecon nuclei example.com
```

Windows PowerShell:

```powershell
bladerecon repair
nuclei -update-templates -update-template-dir "$env:USERPROFILE\nuclei-templates"
bladerecon nuclei example.com
```

This means the Nuclei binary exists, but its template store is empty or could not be downloaded.

## Nuclei Timed Out

Symptoms:

```text
Nuclei Status: Timed Out
Reason: timeout after <seconds>s
```

BladeRecon reports timed-out Nuclei runs clearly in `metadata.json`, `scan_state.json`, and the report. The packaged configuration enables `nuclei.enforce_module_timeout` with a 300 second module timeout; you can raise it with `--timeout` for large, justified scans.

For large targets, prefer:

```bash
bladerecon nuclei example.com --profile safe --timeout 900
```

If you do not want a wall-clock limit, disable `nuclei.enforce_module_timeout` in `config.yaml`.

## Nuclei Baseline Is Skipped

When there are no selected intelligence tags, no validated attack surface, and
no high-confidence opportunities, BladeRecon skips baseline-only Nuclei. This is
intentional: a large tag-free scan with no opportunity evidence can consume
runtime without realistic bug bounty value. The report and `nuclei/metadata.json`
show `coverage_strategy: skipped_low_roi_baseline` and the `roi_decision`.

If opportunity evidence exists but only for a small number of hosts,
baseline-only Nuclei is scoped to those hosts and records the decision in
`target_scope`. If the opportunity hosts are stale and no longer appear in the
current alive target list, BladeRecon skips the baseline instead of expanding
back to every alive host.

## Nuclei Runs A Baseline After Smart Tags

When Smart Nuclei selects technology tags, BladeRecon can also run a small
tag-free baseline scan for `critical,high` severities. This is intentional: the
smart pass stays fast, while the baseline reduces the chance of missing an
important template outside the selected tags. The report and
`nuclei/metadata.json` show whether the baseline was applied, completed, failed,
skipped by ROI, or timed out.

## Custom Nuclei Templates Are Rejected

If you pass `--templates`, BladeRecon accepts either a single `.yaml`/`.yml`
file or a directory containing template files. Custom template directories do
not need to look like the official `nuclei-templates` repository.

```bash
bladerecon nuclei --list targets.txt --templates ./my-templates --profile safe
```

BladeRecon normalizes Nuclei target lists before execution, including UTF-8 BOM
files commonly created by Windows editors or PowerShell.

## Rate Limits Or WAF Noise

Use the safe profile when a target starts returning `429`, WAF challenges, or connection resets:

```bash
bladerecon full example.com --profile safe
bladerecon probe example.com --profile safe
bladerecon js example.com --profile safe
bladerecon screenshot example.com --profile safe
bladerecon nuclei example.com --profile safe
bladerecon advanced example.com --profile safe
```

The safe profile lowers concurrency, per-host concurrency, request ceilings, and requests per second. The active profile is shown in reports.

## Advanced Recon Has Few Results

Advanced recon is intentionally low-noise. It does not run a generic dirbuster.

Check:

```bash
bladerecon probe example.com --profile safe
bladerecon js example.com --profile safe
bladerecon endpoints example.com
bladerecon advanced example.com --profile safe
```

Possible causes:

- Historical sources had little data for the target.
- The safe profile request ceilings were reached.
- CSP/security headers did not reference additional assets.
- Content discovery filtered generic 404/soft-404 responses.
- Historical JS references were absent or unavailable.

## Live JavaScript Is Blocked Or 403

If live HTML or JS assets are blocked, BladeRecon can reuse historical JavaScript
references collected by Advanced Recon. Those historical JS artifacts feed the
same endpoint and secret extraction flow, so blocked live pages do not collapse
the JavaScript surface to zero when historical artifacts exist.

## Go Missing

Symptoms:

```text
go | WARN | Go not found on PATH
```

Fix:

1. Install Go from https://go.dev/dl/
2. Restart the terminal.
3. Verify:

```bash
go version
```

## PATH Issues

If a tool is installed but doctor cannot find it:

Windows:

```powershell
$env:Path
```

Add the tool directory to your user PATH, then restart PowerShell.

Common Go bin path:

```text
%USERPROFILE%\go\bin
```

## Permission Issues

Symptoms:

```text
permissions | WARN
```

Fix:

- Run BladeRecon from a writable project directory.
- Avoid protected system folders.
- Check antivirus or endpoint protection if files are locked.
- Use a custom output directory:

```bash
bladerecon full example.com -o results
```

## Empty Results

Empty results can be normal for invalid or low-surface targets.

Check:

```bash
bladerecon subdomain example.com
bladerecon probe example.com
type results\example.com\subdomains\subdomains.txt
type results\example.com\probe\alive.txt
```

Possible causes:

- Passive sources returned no data.
- Target has no alive HTTP services.
- Network, DNS, or proxy problems.
- Source rate limits or outages.

## No Parameters

Parameter discovery uses historical sources first, then local outputs such as endpoints, JavaScript files, and alive URLs.

If no URL sources exist:

```text
Parameter discovery skipped
Reason: No URL sources available
```

Run:

```bash
bladerecon probe example.com
bladerecon js example.com
bladerecon endpoints example.com
bladerecon param example.com
```

## Skipped Modules

Skipped does not mean failed.

Common skip states:

| Module | Reason | Action |
| --- | --- | --- |
| Screenshots | Chromium browser not installed | `python -m playwright install chromium` |
| Nuclei | Binary not installed | Install Go and Nuclei |
| Nuclei | Templates unavailable | Run `bladerecon repair` or `nuclei -update-templates` |
| Nuclei | Timed Out | Increase `--timeout`, use `--profile safe`, or omit `--timeout` |
| Parameters | No URL sources available | Run probe/js/endpoints first |
| Advanced | No valid scan found | Run probe/js/endpoints/intelligence first |
| Chaos | API key not configured | Add a Chaos API key in `config.yaml` |

## Cache Issues

Show cache:

```bash
bladerecon cache info
```

Clear cache:

```bash
bladerecon cache clear
```

If files are locked on Windows, BladeRecon warns and continues cleanup safely.

## Docker Issues

Build:

```bash
docker build -t bladerecon .
```

Run doctor:

```bash
docker run --rm bladerecon doctor
```

Persist results:

```bash
docker run --rm -v "%cd%\results:/app/results" bladerecon full example.com
```

If volume mounting fails on Windows, use PowerShell:

```powershell
docker run --rm -v "${PWD}\results:/app/results" bladerecon full example.com
```
