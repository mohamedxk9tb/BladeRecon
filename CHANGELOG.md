# Changelog

## 0.2.0 - 2026-05-29

- Added Advanced Recon intelligence with historical URL collection, historical endpoint/parameter extraction, historical attack-surface correlation, historical JavaScript analysis, low-noise content discovery, security-header asset discovery, and asset prioritization.
- Refined Smart Nuclei to pair technology-tag selection with a lightweight `critical,high` baseline safety net and report the coverage strategy in metadata and reports.
- Improved asset-priority explainability with per-signal scoring details, strongest factors, confidence labels, historical/live distinctions, and clearer report presentation.
- Fixed release-candidate validation issues around custom Nuclei template directories, UTF-8 BOM target lists/artifacts, Nuclei Not Run summary labels, and estimated request metrics.
- Added `advanced` CLI command and integrated it into the full workflow before screenshots and Nuclei.
- Added report sections for Advanced Recon Intelligence, Top Priority Assets, Historical Attack Surface, Interesting Paths, Security Header Assets, and quality-control ratios.
- Added professional Rich CLI branding, status language, summaries, cache commands, resume flow, and version reporting.
- Added passive source integrations for Chaos, BufferOver, URLScan, and optional RapidDNS, Anubis, HackerTarget.
- Added source-tagged subdomain JSON/JSONL outputs and lightweight passive-source cache.
- Added probe fingerprints for server, CDN, WAF, and framework hints.
- Added screenshot target filtering for duplicate titles/content lengths, placeholders, and existing captures.
- Replaced nuclei severity-only behavior and the old full profile label with explicit safe, balanced, and aggressive safety profiles.
- Added request ceilings, per-host concurrency limits, request-rate pacing, and active-profile metadata for probe, JavaScript, screenshots, Nuclei, full scans, and reports.
- Changed Nuclei module timeout handling to monitor-only by default, with configurable wall-clock timeout enforcement and clear Timed Out reporting.
- Added recon intelligence outputs for technology, infrastructure, cloud references, risk scoring, and smart template selection.
- Added JSON/JSONL automation outputs for probe, subdomains, parameters, and nuclei.
- Made the dark report theme the default and improved metrics, screenshot gallery, severity display, search, attack-surface summary, report-logo rendering, active-profile display, and collapsible Performance Analytics.
- Added low-overhead scan and per-module performance metrics for full workflow reports.
- Added release media assets for README showcase, including CLI preview, report preview, and social preview images.
- Hardened target path normalization, fresh module state handling, intelligence preflight validation, and Windows-safe banner rendering.
- Added Docker support, pytest coverage, release metadata alignment, and cleanup rules.

## 0.1.0

- Initial BladeRecon package with subdomain discovery, probing, parameters, screenshots, nuclei wrapper, and reports.
