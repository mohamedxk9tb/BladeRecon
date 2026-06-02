"""Reporting module for BladeRecon.

Generates a Markdown and HTML report combining outputs from other modules.

Saves:
- results/<target>/reports/report.md
- results/<target>/reports/report.html

The module collects:
- subdomains and resolution status
- discovered parameters
- screenshots (relative paths)
- nuclei findings grouped by severity

"""
from __future__ import annotations

import asyncio
import base64
import json
import mimetypes
import os
import re
import shutil
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .. import __version__
from .utils import REPORT_VERSION, check_playwright_chromium, deduplicate_alive_urls, deduplicate_parameters, deduplicate_subdomains, dependency_health, info, nuclei_template_status, print_module_summary, setup_logging, success, target_output_dir, warn

console = Console()

TEMPLATE_DIR = Path(__file__).parents[1] / "templates"
TEMPLATE_DIR = TEMPLATE_DIR.resolve()
PROJECT_ROOT = Path(__file__).parents[2].resolve()
PACKAGE_ASSET_DIR = Path(__file__).parents[1] / "assets"

INTERESTING_PARAM_KEYWORDS = [
    "token",
    "auth",
    "apikey",
    "api_key",
    "access_token",
    "session",
    "password",
    "passwd",
    "secret",
    "jwt",
    "csrf",
]

PARAMETER_VALUE_KEYWORDS = {
    "High": [
        "access_token",
        "refresh_token",
        "api_key",
        "authorization",
        "token",
        "jwt",
        "secret",
        "session",
        "auth",
        "key",
    ],
    "Medium": [
        "account_id",
        "return_url",
        "user_id",
        "redirect",
        "callback",
        "email",
        "username",
        "id",
    ],
    "Low": [
        "filter",
        "page",
        "sort",
        "lang",
        "theme",
        "view",
        "tab",
    ],
}


async def _resolve_host(host: str) -> bool:
    loop = asyncio.get_running_loop()

    def _lookup(h: str) -> bool:
        try:
            socket.gethostbyname(h)
            return True
        except Exception:
            return False

    return await loop.run_in_executor(None, _lookup, host)


async def _resolve_hosts(hosts: List[str]) -> Dict[str, bool]:
    results: Dict[str, bool] = {}

    async def worker(h: str) -> None:
        ok = await _resolve_host(h)
        results[h] = ok

    tasks = [asyncio.create_task(worker(h)) for h in hosts]
    await asyncio.gather(*tasks)
    return results


def _load_subdomains(target_dir: Path) -> List[str]:
    f = target_dir / "subdomains" / "subdomains.txt"
    if not f.exists():
        return []
    return deduplicate_subdomains(f.read_text(encoding="utf-8-sig").splitlines())


def _source_label(source: str) -> str:
    labels = {
        "crtsh": "crt.sh",
        "crt.sh": "crt.sh",
        "alienvault": "AlienVault",
        "chaos": "Chaos",
        "bufferover": "BufferOver",
        "urlscan": "URLScan",
        "rapiddns": "RapidDNS",
        "anubis": "Anubis",
        "hackertarget": "HackerTarget",
        "wordlist": "Wordlist",
        "dns_brute": "DNS Brute",
        "passive": "Passive",
    }
    key = source.strip().lower()
    return labels.get(key, source.strip().replace("_", " ").title() or "Passive")


def _load_subdomain_sources(target_dir: Path) -> Dict[str, List[str]]:
    path = target_dir / "subdomains" / "subdomains.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}
    if not isinstance(data, list):
        return {}

    source_map: Dict[str, List[str]] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        subdomains = deduplicate_subdomains([str(item.get("subdomain") or "")])
        if not subdomains:
            continue
        raw_sources = item.get("sources", item.get("source", "Passive"))
        if isinstance(raw_sources, str):
            raw_sources = [raw_sources]
        if not isinstance(raw_sources, list):
            raw_sources = ["Passive"]
        labels = [_source_label(str(source)) for source in raw_sources if str(source).strip()]
        source_map[subdomains[0]] = labels or ["Passive"]
    return source_map


def _load_parameters(target_dir: Path) -> List[str]:
    f = target_dir / "parameters" / "parameters.txt"
    if not f.exists():
        return []
    return deduplicate_parameters(f.read_text(encoding="utf-8-sig").splitlines())


def _load_discovered_parameters(target_dir: Path) -> List[str]:
    f = target_dir / "parameters" / "parameters_from_urls.txt"
    if not f.exists():
        return []
    return deduplicate_parameters(f.read_text(encoding="utf-8-sig").splitlines())


def _parameter_value_level(name: str) -> str:
    value = str(name or "").strip().lower()
    for level in ("High", "Medium", "Low"):
        for keyword in PARAMETER_VALUE_KEYWORDS[level]:
            if value == keyword or keyword in value:
                return level
    return "Low"


def _parameter_intelligence(parameters: List[str], discovered_parameters: List[str]) -> dict:
    discovered_set = {item.lower() for item in discovered_parameters}
    candidates = [item for item in parameters if item.lower() not in discovered_set]
    levels = {"High": [], "Medium": [], "Low": []}
    for item in parameters:
        levels[_parameter_value_level(item)].append(item)
    return {
        "discovered": discovered_parameters,
        "candidates": candidates,
        "discovered_count": len(discovered_parameters),
        "candidate_count": len(candidates),
        "total_count": len(parameters),
        "high_value": levels["High"],
        "medium_value": levels["Medium"],
        "low_value": levels["Low"],
        "high_count": len(levels["High"]),
        "medium_count": len(levels["Medium"]),
        "low_count": len(levels["Low"]),
    }


def _load_json_list(path: Path) -> List[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _load_js_files(target_dir: Path) -> List[dict]:
    return _load_json_list(target_dir / "js" / "js_files.json")


def _load_endpoints(target_dir: Path) -> List[dict]:
    return _load_json_list(target_dir / "endpoints" / "endpoints.json")


def _load_secrets(target_dir: Path) -> List[dict]:
    rows = _load_json_list(target_dir / "secrets" / "secrets.json")
    for row in rows:
        if not isinstance(row, dict):
            continue
        secret_type = str(row.get("type") or "Generic Secret")
        value = str(row.get("value") or "")
        confidence = str(row.get("confidence") or _secret_confidence(secret_type)).upper()
        row.setdefault("confidence", confidence)
        row.setdefault("risk", _secret_risk(secret_type, confidence))
        row.setdefault("value_preview", _secret_preview(value))
    return rows


def _load_screenshots(target_dir: Path) -> List[str]:
    sdir = target_dir / "screenshots"
    if not sdir.exists():
        return []
    imgs = list(sdir.rglob("*.png"))
    report_dir = target_dir / "reports"
    paths = []
    for path in sorted(imgs):
        rel = os.path.relpath(path, report_dir).replace(os.sep, "/")
        paths.append(quote(rel, safe="/._-~%"))
    return paths


def _load_screenshot_failures(target_dir: Path) -> List[dict]:
    path = target_dir / "screenshots" / "failed_screenshots.txt"
    if not path.exists():
        return []
    failures = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line.strip():
            continue
        if "\t" in line:
            url, reason = line.split("\t", 1)
        else:
            url, reason = line, "Screenshot failed"
        failures.append({"url": url.strip(), "reason": reason.strip() or "Screenshot failed"})
    return failures


def _load_nuclei_findings(target_dir: Path) -> List[dict]:
    nd = target_dir / "nuclei" / "results.jsonl"
    if not nd.exists():
        nd = target_dir / "nuclei" / "results.json"
    if not nd.exists():
        return []
    content = nd.read_text(encoding="utf-8-sig")
    if nd.suffix == ".json":
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return [item for item in data if isinstance(item, dict)]
            if isinstance(data, dict):
                return [data]
        except Exception:
            pass
    lines = [l for l in content.splitlines() if l.strip()]
    findings = []
    for line in lines:
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                findings.append(item)
        except Exception:
            continue
    return findings


def _load_nuclei_metadata(target_dir: Path) -> dict:
    path = target_dir / "nuclei" / "metadata.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _load_root_json(target_dir: Path, name: str, default: object) -> object:
    path = target_dir / name
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return default


def _next_investigation_targets(asset_priority: dict, content_rows: List[dict], historical_diff: dict) -> List[dict]:
    targets: List[dict] = []
    if isinstance(asset_priority, dict):
        for item in asset_priority.get("top_assets", [])[:5]:
            if not isinstance(item, dict):
                continue
            strongest = item.get("strongest_factors") if isinstance(item.get("strongest_factors"), list) else []
            reason = strongest[0].get("reason") if strongest and isinstance(strongest[0], dict) else ", ".join(item.get("reasons", [])[:2])
            targets.append({"target": item.get("asset", ""), "type": "Priority asset", "reason": reason or "Highest combined recon score"})
    for item in content_rows[:3]:
        if isinstance(item, dict) and item.get("url"):
            targets.append({"target": item.get("url"), "type": "Interesting path", "reason": item.get("reason") or item.get("signal") or "Focused content discovery hit"})
    if isinstance(historical_diff, dict):
        for url in historical_diff.get("historical_and_currently_alive", [])[:3]:
            targets.append({"target": url, "type": "Historical live asset", "reason": "Historical endpoint is tied to a currently alive host"})
        for url in historical_diff.get("historical_only", [])[:2]:
            targets.append({"target": url, "type": "Historical-only asset", "reason": "Historical endpoint did not appear in current endpoint artifacts"})
    seen = set()
    deduped = []
    for item in targets:
        key = str(item.get("target") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped[:8]


def _load_intelligence_file(target_dir: Path, name: str, default: object) -> object:
    path = target_dir / "intelligence" / name
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        return data
    except Exception:
        return default


def _load_probe_results(target_dir: Path) -> List[dict]:
    path = target_dir / "probe" / "probe.json"
    if not path.exists():
        path = target_dir / "probe" / "probe.jsonl"
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8-sig")
        if path.suffix == ".json":
            data = json.loads(text)
            return data if isinstance(data, list) else []
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    except Exception:
        return []


def _load_technology_results(target_dir: Path) -> List[dict]:
    return _load_json_list(target_dir / "technologies" / "technologies.json")


def _group_findings_by_severity(findings: List[dict]) -> Dict[str, List[dict]]:
    groups: Dict[str, List[dict]] = {sev: [] for sev in ("critical", "high", "medium", "low", "info", "unknown")}
    for f in findings:
        sev = str(f.get("info", {}).get("severity") or f.get("severity") or "unknown").lower()
        groups.setdefault(sev if sev in groups else "unknown", []).append(f)
    return {sev: items for sev, items in groups.items() if items}


def _load_alive_hosts(target_dir: Path) -> List[str]:
    f = target_dir / "probe" / "alive.txt"
    if not f.exists():
        return []
    return deduplicate_alive_urls(f.read_text(encoding="utf-8-sig").splitlines())


def _alive_hostnames(alive_hosts: List[str]) -> Set[str]:
    hosts: Set[str] = set()
    for item in alive_hosts:
        parsed = urlparse(item)
        hosts.add((parsed.hostname or item).lower())
    return hosts


def _host_from_url(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return (parsed.hostname or value).lower().rstrip(".")


def _interesting_parameters(params: List[str]) -> List[str]:
    interesting = [p for p in params if any(k in p.lower() for k in INTERESTING_PARAM_KEYWORDS)]
    return interesting


def _load_scan_metadata(target_dir: Path) -> dict:
    f = target_dir / "logs" / "scan_meta.json"
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def _load_scan_state(target_dir: Path) -> dict:
    f = target_dir / "scan_state.json"
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def _asset_data_uri(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    try:
        mime = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        payload = base64.b64encode(path.read_bytes()).decode("ascii")
        return f"data:{mime};base64,{payload}"
    except Exception:
        return ""


def _status_label(status: str, has_artifact: bool = False, count: int = 0) -> str:
    value = str(status or "").strip().lower()
    if value == "completed" and count == 0:
        return "Zero Findings" if has_artifact else "Completed"
    if value == "timed_out":
        return "Timed Out"
    if value in {"completed", "failed", "skipped"}:
        return value.title()
    return "Not Run"


def _estimate_traffic(target_dir: Path) -> Dict[str, int]:
    rows = _load_probe_results(target_dir)
    requests = len(rows)
    responses = len([row for row in rows if isinstance(row, dict) and row.get("status_code")])
    for metadata_path in (
        target_dir / "probe" / "metadata.json",
        target_dir / "js" / "metadata.json",
        target_dir / "screenshots" / "metadata.json",
        target_dir / "nuclei" / "metadata.json",
        target_dir / "advanced_metadata.json",
    ):
        if not metadata_path.exists():
            continue
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
        except Exception:
            continue
        if metadata_path.name == "advanced_metadata.json":
            requests += int(metadata.get("requests_sent", 0) or 0)
        elif metadata_path.parent.name == "js":
            requests += int(metadata.get("html_requests", 0) or 0)
            requests += int(metadata.get("download_requests", 0) or 0)
        elif metadata_path.parent.name == "screenshots":
            requests += int(metadata.get("queued", 0) or 0)
        elif metadata_path.parent.name == "nuclei":
            targets = int(metadata.get("targets_count", 0) or 0)
            templates = int(metadata.get("templates_executed", metadata.get("template_candidates", 0)) or 0)
            requests += max(0, targets * templates)
            baseline = metadata.get("baseline_scan", {}) if isinstance(metadata.get("baseline_scan"), dict) else {}
            if baseline.get("applied"):
                baseline_targets = int(baseline.get("targets_count", 0) or 0)
                baseline_templates = int(baseline.get("templates_executed", baseline.get("template_candidates", 0)) or 0)
                requests += max(0, baseline_targets * baseline_templates)
    return {"total_requests_sent": requests, "total_responses_received": responses}


def _display_time(value: object) -> str:
    raw = str(value or "").strip()
    if not raw or raw == "Not recorded":
        return "Not recorded"
    normalized = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return raw


def _build_performance(scan_meta: dict, scan_state: dict, target_dir: Path) -> Dict[str, object]:
    modules = scan_state.get("modules", {}) if isinstance(scan_state, dict) else {}
    performance = scan_meta.get("performance", {}) if isinstance(scan_meta, dict) else {}
    traffic = _estimate_traffic(target_dir)
    if isinstance(performance, dict):
        traffic["total_requests_sent"] = max(traffic["total_requests_sent"], int(performance.get("total_requests_sent", 0) or 0))
        traffic["total_responses_received"] = max(traffic["total_responses_received"], int(performance.get("total_responses_received", 0) or 0))
    module_rows = []
    for name in ("subdomains", "probe", "js", "endpoints", "secrets", "parameters", "intelligence", "advanced", "screenshots", "nuclei"):
        state = modules.get(name, {}) if isinstance(modules, dict) else {}
        if not isinstance(state, dict):
            state = {}
        perf = state.get("performance", {}) if isinstance(state.get("performance"), dict) else {}
        module_rows.append(
            {
                "module": name.title() if name != "js" else "JS",
                "status": _status_label(str(state.get("status") or "")),
                "duration_seconds": round(float(state.get("duration_seconds") or 0.0), 2),
                "peak_ram_mb": round(float(perf.get("peak_ram_mb") or 0.0), 2),
                "average_ram_mb": round(float(perf.get("average_ram_mb") or 0.0), 2),
            }
        )
    active_rows = [row for row in module_rows if row["status"] != "Not Run"]
    top_slowest = sorted(active_rows, key=lambda row: float(row.get("duration_seconds") or 0.0), reverse=True)[:3]
    top_ram = sorted(active_rows, key=lambda row: float(row.get("peak_ram_mb") or 0.0), reverse=True)[:3]
    scan_start_raw = performance.get("scan_start_time", scan_meta.get("started_at", "Not recorded")) if isinstance(performance, dict) else "Not recorded"
    scan_end_raw = performance.get("scan_end_time", scan_meta.get("updated_at", "Not recorded")) if isinstance(performance, dict) else "Not recorded"
    return {
        "scan_start_time": _display_time(scan_start_raw),
        "scan_start_time_raw": scan_start_raw,
        "scan_end_time": _display_time(scan_end_raw),
        "scan_end_time_raw": scan_end_raw,
        "total_duration": scan_meta.get("duration_human", "Not recorded"),
        "peak_ram_mb": round(float(performance.get("peak_ram_mb") or 0.0), 2) if isinstance(performance, dict) else 0.0,
        "average_ram_mb": round(float(performance.get("average_ram_mb") or 0.0), 2) if isinstance(performance, dict) else 0.0,
        "peak_cpu_percent": round(float(performance.get("peak_cpu_percent") or 0.0), 2) if isinstance(performance, dict) else 0.0,
        "average_cpu_percent": round(float(performance.get("average_cpu_percent") or 0.0), 2) if isinstance(performance, dict) else 0.0,
        "total_requests_sent": traffic["total_requests_sent"],
        "total_responses_received": traffic["total_responses_received"],
        "traffic_note": "Request counts are estimated from module metadata when available, including probe, JavaScript, screenshots, advanced recon, and Nuclei template-target combinations. Responses are HTTP probe rows with status codes.",
        "cpu_note": "CPU values are process CPU core utilization samples. Values above 100% can occur when work spans more than one logical core.",
        "module_count": len(active_rows),
        "top_slowest_modules": top_slowest,
        "top_ram_consumers": top_ram,
        "modules": module_rows,
    }
def _nuclei_binary_available() -> bool:
    return shutil.which("nuclei") is not None


def _normalize_skip_reason(reason: str) -> str:
    value = str(reason or "").strip()
    if value.lower() == "missing nuclei dependency":
        return "Binary not installed"
    return value or "Missing Dependency"


def _clean_version(value: str) -> str:
    match = re.search(r"(\d+(?:\.\d+){1,3})", value)
    return match.group(1) if match else ""


def _secret_confidence(secret_type: str) -> str:
    high = {
        "AWS Access Key",
        "Slack Token",
        "GitHub Token",
        "GitLab Token",
        "Private Key",
        "JWT Token",
        "Webhook URL",
    }
    medium = {"Bearer Token", "Session Token", "OAuth Token", "Stripe Key"}
    if secret_type in high:
        return "HIGH"
    if secret_type in medium:
        return "MEDIUM"
    return "LOW"


def _secret_risk(secret_type: str, confidence: str) -> str:
    if confidence == "HIGH":
        return "High"
    if confidence == "MEDIUM":
        return "Medium"
    if "client" in secret_type.lower() or "analytics" in secret_type.lower() or "tracking" in secret_type.lower():
        return "Low"
    return "Low"


def _secret_preview(value: str) -> str:
    clean = str(value or "").strip()
    if len(clean) <= 18:
        return clean
    return f"{clean[:8]}...{clean[-6:]}"


def _technology_display_name(value: str) -> str:
    raw = str(value or "").strip()
    lower = raw.lower()
    version = _clean_version(raw)
    names = [
        ("cloudflare waf", "Cloudflare WAF"),
        ("akamai waf", "Akamai WAF"),
        ("cloudfront", "CloudFront"),
        ("cloudflare", "Cloudflare"),
        ("github.com", "GitHub Pages"),
        ("github pages", "GitHub Pages"),
        ("akamai", "Akamai"),
        ("fastly", "Fastly"),
        ("microsoft-iis", "IIS"),
        ("iis", "IIS"),
        ("litespeed", "LiteSpeed"),
        ("nginx", "Nginx"),
        ("apache", "Apache"),
        ("asp.net core", "ASP.NET Core"),
        ("aspnetcore", "ASP.NET Core"),
        ("asp.net", "ASP.NET"),
        ("express", "Express.js"),
        ("next.js", "Next.js"),
        ("__next", "Next.js"),
        ("wordpress", "WordPress"),
        ("drupal", "Drupal"),
        ("joomla", "Joomla"),
        ("laravel", "Laravel"),
        ("django", "Django"),
        ("flask", "Flask"),
        ("react", "React"),
        ("angular", "Angular"),
        ("vue", "Vue"),
    ]
    for needle, label in names:
        if needle in lower:
            if label in {"Nginx", "Apache", "IIS", "LiteSpeed"} and version:
                return f"{label} {version}"
            return label
    return raw.replace("_", " ").strip().title()


def _technology_category(name: str) -> str:
    lower = name.lower()
    if lower in {"cloudflare", "cloudfront", "akamai", "fastly"}:
        return "CDN"
    if any(item in lower for item in ("cloudflare waf", "akamai waf", "sucuri", "imperva")):
        return "WAF"
    if any(item in lower for item in ("nginx", "apache", "iis", "litespeed")):
        return "Web Server"
    if any(item in lower for item in ("asp.net", "laravel", "django", "flask", "express")):
        return "Framework"
    if any(item in lower for item in ("wordpress", "drupal", "joomla")):
        return "CMS"
    if any(item in lower for item in ("react", "next.js", "angular", "vue")):
        return "Frontend"
    if any(item in lower for item in ("github pages", "heroku", "vercel", "netlify")):
        return "Hosting"
    if any(item in lower for item in ("graphql", "swagger", "openapi", "rest")):
        return "API"
    return "Infrastructure"


def _technology_base_and_role(value: str, category: Optional[str] = None) -> Tuple[str, str]:
    name = _technology_display_name(value)
    if name.endswith(" WAF"):
        return name[:-4], "WAF"
    return name, category or _technology_category(name)


def _confidence_rank(value: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(str(value or "").strip().lower(), 0)


def _add_technology(
    records: Dict[str, dict],
    value: str,
    category: Optional[str] = None,
    confidence: str = "Medium",
    sources: Optional[List[str]] = None,
    evidence: Optional[List[str]] = None,
    host: str = "",
) -> None:
    name, role = _technology_base_and_role(value, category)
    if not name:
        return
    key = name.lower()
    sources = [str(item) for item in (sources or []) if str(item).strip()]
    evidence = [str(item) for item in (evidence or []) if str(item).strip()]
    existing = records.get(key)
    if existing:
        existing["count"] += 1
        if role not in existing["roles"]:
            existing["roles"].append(role)
        if existing["category"] == "Infrastructure" and role != "Infrastructure":
            existing["category"] = role
        if _confidence_rank(confidence) > _confidence_rank(existing.get("confidence", "")):
            existing["confidence"] = confidence.title()
        existing["sources"].update(sources)
        existing["evidence"].update(evidence)
        if host:
            existing["hosts"].add(host)
        return
    records[key] = {
        "name": name,
        "category": role,
        "roles": [role],
        "count": 1,
        "confidence": confidence.title(),
        "sources": set(sources),
        "evidence": set(evidence),
        "hosts": {host} if host else set(),
    }


def _normalized_technology_records(technology_results: List[dict], probe_results: List[dict]) -> List[dict]:
    records: Dict[str, dict] = {}
    if technology_results:
        for row in technology_results:
            host = str(row.get("host") or "")
            details = row.get("technologies", []) if isinstance(row.get("technologies"), list) else []
            for detail in details:
                if not isinstance(detail, dict):
                    continue
                _add_technology(
                    records,
                    str(detail.get("name") or ""),
                    confidence=str(detail.get("confidence") or "Medium"),
                    sources=[str(item) for item in detail.get("sources", [])] if isinstance(detail.get("sources"), list) else [],
                    evidence=[str(item) for item in detail.get("evidence", [])] if isinstance(detail.get("evidence"), list) else [],
                    host=host,
                )
            for tech in row.get("detected", []):
                _add_technology(records, str(tech), sources=["Technology Artifact"], host=host)

    for row in probe_results:
        if row.get("cdn"):
            _add_technology(records, str(row["cdn"]), "CDN", "High", ["CDN Header"], [str(row["cdn"])], _host_from_url(str(row.get("final_url") or row.get("url") or "")))
        if row.get("waf"):
            _add_technology(records, f"{row['waf']} WAF", "WAF", "High", ["WAF Header"], [str(row["waf"])], _host_from_url(str(row.get("final_url") or row.get("url") or "")))
        if row.get("server"):
            _add_technology(records, str(row["server"]), "Web Server", "High", ["Server Header"], [str(row["server"])], _host_from_url(str(row.get("final_url") or row.get("url") or "")))
        detected = list(row.get("technologies", []) or [])
        for tech in detected:
            _add_technology(records, str(tech), sources=["Probe Fingerprint"], host=_host_from_url(str(row.get("final_url") or row.get("url") or "")))

    normalized = []
    for item in records.values():
        item["sources"] = sorted(item.get("sources", set()))
        item["evidence"] = sorted(item.get("evidence", set()))
        item["hosts"] = sorted(item.get("hosts", set()))
        normalized.append(item)
    return sorted(normalized, key=lambda item: (item["category"], item["name"].lower()))


def _technology_distribution(technology_records: List[dict]) -> Dict[str, int]:
    return {
        item["name"]: int(item["count"])
        for item in sorted(technology_records, key=lambda row: (-int(row["count"]), row["name"].lower()))
    }


def _technology_categories(technology_records: List[dict]) -> Dict[str, List[str]]:
    order = ["Infrastructure", "CDN", "Web Server", "Framework", "CMS", "Hosting", "WAF", "Frontend", "API"]
    grouped: Dict[str, List[str]] = {category: [] for category in order}
    for item in technology_records:
        roles = item.get("roles") or [item.get("category", "Infrastructure")]
        for role in roles:
            grouped.setdefault(role, []).append(item["name"])
    return {category: sorted(set(values)) for category, values in grouped.items() if values}


def _technology_roles(technology_records: List[dict]) -> Dict[str, List[str]]:
    return {
        item["name"]: sorted(set(item.get("roles") or [item.get("category", "Infrastructure")]))
        for item in sorted(technology_records, key=lambda row: row["name"].lower())
    }


def _attack_surface(probe_results: List[dict], subdomains: List[str], alive_hosts: List[str], technology_results: Optional[List[dict]] = None) -> dict:
    technology_records = _normalized_technology_records(technology_results or [], probe_results)
    distribution = _technology_distribution(technology_records)
    categories = _technology_categories(technology_records)
    technologies = sorted(distribution)
    wafs = sorted({str(row.get("waf")) for row in probe_results if row.get("waf")})
    cdns = sorted({str(row.get("cdn")) for row in probe_results if row.get("cdn")})
    return {
        "total_assets": len(subdomains) or len(probe_results),
        "alive_assets": len(alive_hosts),
        "technologies": technologies,
        "technology_count": len(technologies),
        "technology_distribution": distribution,
        "most_common_technologies": list(distribution.items())[:8],
        "technology_categories": categories,
        "technology_roles": _technology_roles(technology_records),
        "technology_details": technology_records,
        "technology_stack": technologies[:6],
        "waf_detected": wafs,
        "cdn_detected": cdns,
        "servers": categories.get("Web Server", []),
    }


def _render_markdown(context: dict, out_md: Path) -> None:
    lines: List[str] = []
    lines.append(f"# BladeRecon Report: {context.get('target')}")
    lines.append("")
    lines.append(f"Generated: {context.get('timestamp')}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total subdomains: {len(context.get('subdomains', []))}")
    lines.append(f"- Alive hosts: {len(context.get('alive_hosts', []))}")
    lines.append(f"- JavaScript files: {len(context.get('js_files', []))}")
    lines.append(f"- Endpoints found: {len(context.get('endpoints', []))}")
    lines.append(f"- Secrets detected: {len(context.get('secrets', []))}")
    lines.append(f"- Parameters found: {context.get('parameters_status', len(context.get('parameters', [])))}")
    param_intel = context.get("parameter_intelligence", {})
    if not context.get("parameters_skipped_reason"):
        lines.append(f"- Discovered parameters: {param_intel.get('discovered_count', 0)}")
        lines.append(f"- Candidate parameters: {param_intel.get('candidate_count', 0)}")
    lines.append(f"- Screenshots: {context.get('screenshots_status', len(context.get('screenshots', [])))}")
    md_vulns = sum(len(v) for v in context.get('nuclei', {}).values())
    lines.append(f"- Vulnerabilities (nuclei findings): {context.get('nuclei_status', md_vulns)}")
    if context.get("scan_duration"):
        lines.append(f"- Scan duration: {context.get('scan_duration')}")
    lines.append("")

    perf = context.get("performance", {})
    lines.append("## Performance Analytics")
    lines.append("")
    lines.append(f"- Scan Start Time: {perf.get('scan_start_time', 'Not recorded')}")
    lines.append(f"- Scan End Time: {perf.get('scan_end_time', 'Not recorded')}")
    lines.append(f"- Total Duration: {perf.get('total_duration', 'Not recorded')}")
    lines.append(f"- Peak RAM Usage: {perf.get('peak_ram_mb', 0)} MB")
    lines.append(f"- Average RAM Usage: {perf.get('average_ram_mb', 0)} MB")
    lines.append(f"- Peak CPU Core Utilization: {perf.get('peak_cpu_percent', 0)}%")
    lines.append(f"- Average CPU Core Utilization: {perf.get('average_cpu_percent', 0)}%")
    lines.append(f"- Estimated Requests Attempted: {perf.get('total_requests_sent', 0)}")
    lines.append(f"- HTTP Responses Recorded: {perf.get('total_responses_received', 0)}")
    if perf.get("traffic_note"):
        lines.append(f"- Traffic Metrics Note: {perf.get('traffic_note')}")
    if perf.get("cpu_note"):
        lines.append(f"- CPU Metrics Note: {perf.get('cpu_note')}")
    lines.append(f"- Module Count: {perf.get('module_count', 0)}")
    lines.append("")
    if perf.get("top_slowest_modules"):
        lines.append("### Top Slowest Modules")
        lines.append("")
        for index, row in enumerate(perf.get("top_slowest_modules", []), start=1):
            lines.append(f"{index}. {row.get('module')} - {row.get('duration_seconds')}s")
        lines.append("")
    if perf.get("top_ram_consumers"):
        lines.append("### Top RAM Consumers")
        lines.append("")
        for index, row in enumerate(perf.get("top_ram_consumers", []), start=1):
            lines.append(f"{index}. {row.get('module')} - {row.get('peak_ram_mb')} MB peak")
        lines.append("")
    lines.append("| Module | Status | Duration | Peak RAM | Average RAM |")
    lines.append("| --- | --- | ---: | ---: | ---: |")
    for row in perf.get("modules", []):
        lines.append(f"| {row.get('module')} | {row.get('status')} | {row.get('duration_seconds')}s | {row.get('peak_ram_mb')} MB | {row.get('average_ram_mb')} MB |")
    lines.append("")

    lines.append("## Dependencies")
    lines.append("")
    for dep in context.get("dependencies", []):
        detail = dep.get("reason") or dep.get("details") or ""
        lines.append(f"- {dep.get('name')}: {dep.get('status')}{f' ({detail})' if detail else ''}")
    lines.append("")

    surface = context.get("attack_surface", {})
    lines.append("## Attack Surface Summary")
    lines.append("")
    lines.append(f"- Total assets: {surface.get('total_assets', 0)}")
    lines.append(f"- Alive assets: {surface.get('alive_assets', 0)}")
    lines.append(f"- Technologies: {', '.join(surface.get('technologies', [])) or 'No data'}")
    lines.append(f"- WAF detected: {', '.join(surface.get('waf_detected', [])) or 'No data'}")
    lines.append(f"- CDN detected: {', '.join(surface.get('cdn_detected', [])) or 'No data'}")
    lines.append("")

    distribution = surface.get("technology_distribution", {})
    lines.append("## Technology Overview")
    lines.append("")

    risk_score = context.get("risk_score", {})
    infrastructure = context.get("infrastructure", {})
    cloud_assets = context.get("cloud_assets", [])
    historical_dns = context.get("historical_dns", {})
    template_intelligence = context.get("template_intelligence", {})

    lines.append("## Intelligence")
    lines.append("")
    if risk_score:
        lines.append(f"- Risk Score: {risk_score.get('score', 0)}/100 ({risk_score.get('level', 'Not classified')})")
        for factor in risk_score.get("factors", []):
            lines.append(f"  - {factor}")
    if infrastructure:
        lines.append(f"- Infrastructure assets: {len(infrastructure.get('assets', []))}")
        for asset in infrastructure.get("assets", [])[:10]:
            lines.append(f"  - {asset.get('host', '')} -> {asset.get('ip', '') or 'No resolved IP'}")
    if cloud_assets:
        lines.append(f"- Cloud assets: {len(cloud_assets)}")
        for asset in cloud_assets[:10]:
            lines.append(f"  - {asset.get('type')}: {asset.get('value')}")
    if historical_dns:
        lines.append(f"- Historical hosts: {len(historical_dns.get('historical_hosts', []))}")
    if template_intelligence:
        lines.append(f"- Smart Nuclei tags: {', '.join(template_intelligence.get('selected_tags', [])) or 'No tag selection'}")
        lines.append(f"- Templates available: {template_intelligence.get('templates_available', 'Not Run')}")
    advanced_meta = context.get("advanced_metadata", {})
    if advanced_meta:
        historical = advanced_meta.get("historical", {})
        content = advanced_meta.get("content_discovery", {})
        historical_js = advanced_meta.get("historical_js", {})
        security_headers = advanced_meta.get("security_headers", {})
        lines.append(f"- Historical URLs: {historical.get('urls', 0)}")
        lines.append(f"- Historical endpoints: {historical.get('endpoints', 0)}")
        lines.append(f"- Interesting paths: {content.get('findings', 0)}")
        lines.append(f"- Security header assets: {security_headers.get('assets', 0)}")
        lines.append(f"- Historical JS endpoints: {historical_js.get('endpoints', 0)}")
    lines.append("")
    if distribution:
        for tech, count in distribution.items():
            roles = ", ".join(surface.get("technology_roles", {}).get(tech, []))
            suffix = f" ({roles})" if roles else ""
            lines.append(f"- {tech}: {count}{suffix}")
        details = surface.get("technology_details", [])
        if details:
            lines.append("")
            lines.append("| Technology | Confidence | Sources | Evidence | Hosts |")
            lines.append("| --- | --- | --- | --- | --- |")
            for item in details:
                sources = ", ".join(item.get("sources", [])) or "Not recorded"
                evidence = "; ".join(item.get("evidence", [])[:2]) or "Not recorded"
                hosts = ", ".join(item.get("hosts", [])[:3]) or "Not recorded"
                lines.append(f"| {item.get('name')} | {item.get('confidence', 'Medium')} | {sources} | {evidence} | {hosts} |")
    else:
        lines.append("- No technology data available")
    lines.append("")

    lines.append("## Subdomains")
    lines.append("")
    alive_names = set(context.get('alive_hostnames', []))
    for s in context.get('subdomains', []):
        status = "alive" if s.lower() in alive_names else "unknown"
        lines.append(f"- {s} - {status}")
    lines.append("")

    lines.append("## Interesting Parameters")
    lines.append("")

    lines.append("## Advanced Recon Intelligence")
    lines.append("")
    historical_diff = context.get("historical_diff", {})
    asset_priority = context.get("asset_priority", {})
    content_rows = context.get("content_discovery", [])
    header_assets = context.get("security_header_assets", {})
    historical_js_data = context.get("historical_js", {})
    lines.append(f"- Historical URLs: {len(context.get('historical_urls', []))}")
    lines.append(f"- Historical endpoints: {len(context.get('historical_endpoints', []))}")
    lines.append(f"- Removed APIs: {len(historical_diff.get('removed_apis', [])) if isinstance(historical_diff, dict) else 0}")
    lines.append(f"- Legacy paths: {len(historical_diff.get('legacy_paths', [])) if isinstance(historical_diff, dict) else 0}")
    lines.append(f"- Historical + currently alive: {len(historical_diff.get('historical_and_currently_alive', [])) if isinstance(historical_diff, dict) else 0}")
    lines.append(f"- Historical only: {len(historical_diff.get('historical_only', [])) if isinstance(historical_diff, dict) else 0}")
    lines.append(f"- Historical unresolved: {len(historical_diff.get('historical_unresolved', [])) if isinstance(historical_diff, dict) else 0}")
    lines.append(f"- Interesting paths: {len(content_rows)}")
    lines.append(f"- Header assets: {len(header_assets.get('assets', [])) if isinstance(header_assets, dict) else 0}")
    lines.append(f"- Historical JS endpoints: {len(historical_js_data.get('endpoints', [])) if isinstance(historical_js_data, dict) else 0}")
    lines.append("")
    if isinstance(asset_priority, dict) and asset_priority.get("top_assets"):
        lines.append("### Top Priority Assets")
        lines.append("")
        lines.append("| Asset | Score | Confidence | Strongest Factors |")
        lines.append("| --- | --- | --- | --- |")
        for item in asset_priority.get("top_assets", [])[:10]:
            if not isinstance(item, dict):
                continue
            strongest = item.get("strongest_factors") if isinstance(item.get("strongest_factors"), list) else []
            reasons = "; ".join(str(factor.get("reason") or factor.get("signal") or "") for factor in strongest[:3] if isinstance(factor, dict)) or ", ".join(item.get("reasons", [])[:3])
            lines.append(f"| {item.get('asset')} | {item.get('score')}/100 | {item.get('confidence', 'Medium')} | {reasons or 'Not recorded'} |")
        lines.append("")
    next_targets = context.get("next_investigation_targets", [])
    if next_targets:
        lines.append("### Suggested Next Investigation Targets")
        lines.append("")
        for item in next_targets:
            lines.append(f"- {item.get('target')} - {item.get('type')}: {item.get('reason')}")
        lines.append("")
    if not context.get("parameters_skipped_reason"):
        lines.append(f"- Discovered Parameters: {param_intel.get('discovered_count', 0)}")
        lines.append(f"- Candidate Parameters: {param_intel.get('candidate_count', 0)}")
        lines.append(f"- Total Parameters: {param_intel.get('total_count', 0)}")
        lines.append(f"- High Value Parameters: {param_intel.get('high_count', 0)}")
        lines.append(f"- Medium Value Parameters: {param_intel.get('medium_count', 0)}")
        lines.append(f"- Low Value Parameters: {param_intel.get('low_count', 0)}")
        lines.append("")
    for p in context.get('interesting_parameters', []):
        lines.append(f"- {p}")
    lines.append("")

    lines.append("## Screenshots")
    lines.append("")
    for img in context.get('screenshots', []):
        lines.append(f"- ![]({img})")
    lines.append("")

    lines.append("## JavaScript Files")
    lines.append("")
    for item in context.get("js_files", []):
        lines.append(f"- {item.get('url')}")
    lines.append("")

    lines.append("## Endpoints")
    lines.append("")
    for item in context.get("endpoints", []):
        lines.append(f"- {item.get('endpoint')}")
    lines.append("")

    lines.append("## Secrets Detected")
    lines.append("")
    for item in context.get("secrets", []):
        lines.append(
            f"- **{item.get('type')}** [{item.get('confidence', 'LOW')}] "
            f"{item.get('value_preview', '')} in {item.get('source')} "
            f"(Risk: {item.get('risk', 'Low')})"
        )
    lines.append("")

    lines.append("## Nuclei Findings by Severity")
    lines.append("")
    metadata = context.get("nuclei_metadata", {})
    if metadata:
        lines.append(f"- Coverage strategy: {metadata.get('coverage_strategy', 'profile/default')}")
        baseline = metadata.get("baseline_scan", {}) if isinstance(metadata.get("baseline_scan"), dict) else {}
        if baseline:
            applied = "applied" if baseline.get("applied") else "not applied"
            lines.append(f"- Baseline safety net: {applied}, status {baseline.get('status', 'not_applicable')}, severity {baseline.get('severity', 'critical,high')}")
        lines.append(f"- Templates executed: {metadata.get('templates_executed', 'Not recorded')}")
        lines.append(f"- Templates skipped: {metadata.get('templates_skipped', 'Not recorded')}")
        lines.append(f"- Execution duration: {metadata.get('duration_seconds', 'Not recorded')}s")
        lines.append(f"- Findings count: {metadata.get('findings_count', context.get('nuclei_count', 0))}")
        lines.append("")
    for sev, items in context.get('nuclei', {}).items():
        lines.append(f"### {sev} ({len(items)})")
        lines.append("")
        for it in items:
            name = it.get('info', {}).get('name') or it.get('template')
            host = it.get('host') or it.get('matched')
            lines.append(f"- **{name}** on {host}")
        lines.append("")

    out_md.write_text("\n".join(lines), encoding="utf-8")


def _render_html(context: dict, out_html: Path) -> None:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    tpl = env.get_template("report.html.j2")
    html = tpl.render(**context)
    out_html.write_text(html, encoding="utf-8")


def _display_path(path: Path) -> Path:
    """Return a compact path for CLI display when possible."""
    try:
        return path.relative_to(Path.cwd())
    except ValueError:
        return path


def run(target: str, output: Path = Path("results"), scan_duration: Optional[str] = None) -> None:
    """Generate combined Markdown and HTML reports for `target`.

    The `output` is the base results folder where per-target subfolders exist.
    """
    target = target.strip()
    target_dir = target_output_dir(output, target)
    if not target_dir.exists():
        console.print(f"[red]Results for target not found:[/] {target_dir}")
        return
    log = setup_logging(target, output, "report")
    started = time.perf_counter()

    info(f"Generating report for {target}")
    log.info("Generating report for %s", target)

    subdomains = _load_subdomains(target_dir)
    subdomain_sources = _load_subdomain_sources(target_dir)
    alive_hosts = _load_alive_hosts(target_dir)
    alive_hostnames = sorted(_alive_hostnames(alive_hosts))
    js_files = _load_js_files(target_dir)
    endpoints = _load_endpoints(target_dir)
    secrets = _load_secrets(target_dir)
    screenshots_available = (target_dir / "screenshots").exists()
    nuclei_available = (target_dir / "nuclei" / "results.jsonl").exists() or (target_dir / "nuclei" / "results.json").exists()
    nuclei_skipped_reason = "" if nuclei_available or _nuclei_binary_available() else "Binary not installed"
    nuclei_state_status = "skipped" if nuclei_skipped_reason else ""
    nuclei_status_label = "Skipped"
    if not nuclei_available and not nuclei_skipped_reason and not nuclei_template_status()["ok"]:
        nuclei_skipped_reason = "templates unavailable. Run: nuclei -ut"
        nuclei_state_status = "skipped"
    screenshots = _load_screenshots(target_dir)
    screenshot_failures = _load_screenshot_failures(target_dir)
    nuclei_findings = _load_nuclei_findings(target_dir)
    nuclei_metadata = _load_nuclei_metadata(target_dir)
    infrastructure = _load_intelligence_file(target_dir, "infrastructure.json", {})
    cloud_assets = _load_intelligence_file(target_dir, "cloud_assets.json", [])
    historical_dns = _load_intelligence_file(target_dir, "historical_dns.json", {})
    risk_score = _load_intelligence_file(target_dir, "risk_score.json", {})
    template_intelligence = _load_intelligence_file(target_dir, "template_intelligence.json", {})
    intelligence_attack_surface = _load_intelligence_file(target_dir, "attack_surface.json", {})
    historical_metadata = _load_json_list(target_dir / "historical" / "urls.json")
    historical_endpoints = _load_json_list(target_dir / "historical" / "endpoints.json")
    historical_diff = _load_root_json(target_dir, "historical_diff.json", {})
    content_discovery = _load_json_list(target_dir / "content_discovery" / "interesting_paths.json")
    security_header_assets = _load_root_json(target_dir, "security_headers_assets.json", {})
    historical_js = {
        "metadata": _load_root_json(target_dir / "historical_js", "metadata.json", {}),
        "endpoints": _load_json_list(target_dir / "historical_js" / "endpoints.json"),
    }
    asset_priority = _load_root_json(target_dir, "asset_priority.json", {})
    next_targets = _next_investigation_targets(asset_priority if isinstance(asset_priority, dict) else {}, content_discovery, historical_diff if isinstance(historical_diff, dict) else {})
    advanced_metadata = _load_root_json(target_dir, "advanced_metadata.json", {})
    probe_results = _load_probe_results(target_dir)
    technology_results = _load_technology_results(target_dir)
    scan_meta = _load_scan_metadata(target_dir)
    scan_state = _load_scan_state(target_dir)
    performance = _build_performance(scan_meta, scan_state, target_dir)

    module_state = scan_state.get("modules", {}) if isinstance(scan_state, dict) else {}
    screenshot_state = module_state.get("screenshots", {}) if isinstance(module_state, dict) else {}
    nuclei_state = module_state.get("nuclei", {}) if isinstance(module_state, dict) else {}
    parameter_state = module_state.get("parameters", {}) if isinstance(module_state, dict) else {}
    parameters_skipped_reason = ""
    if isinstance(parameter_state, dict) and parameter_state.get("status") == "skipped":
        parameters_skipped_reason = _normalize_skip_reason(str(parameter_state.get("error") or "No URLs available for extraction"))
        parameters = []
        discovered_parameters = []
    else:
        parameters = _load_parameters(target_dir)
        discovered_parameters = _load_discovered_parameters(target_dir)
    screenshots_skipped_reason = ""
    if isinstance(screenshot_state, dict) and screenshot_state.get("status") == "skipped":
        screenshots_skipped_reason = _normalize_skip_reason(str(screenshot_state.get("error") or "Missing Dependency"))
    else:
        chromium_ok, chromium_detail = check_playwright_chromium()
        if not screenshots and not chromium_ok:
            screenshots_skipped_reason = _normalize_skip_reason(chromium_detail)
    if isinstance(nuclei_state, dict) and nuclei_state.get("status") in {"skipped", "failed", "timed_out"}:
        nuclei_state_status = str(nuclei_state.get("status") or "skipped")
        nuclei_status_label = nuclei_state_status.title()
        nuclei_skipped_reason = _normalize_skip_reason(str(nuclei_state.get("error") or "Missing Dependency"))
        if "templates unavailable" in nuclei_skipped_reason.lower():
            nuclei_state_status = "skipped"
            nuclei_status_label = "Skipped"

    live_status: Dict[str, bool] = {}
    if subdomains and not alive_hosts:
        console.print("[dim]Resolving subdomains to check live status...[/]")
        try:
            live_status = asyncio.run(_resolve_hosts(subdomains))
        except Exception:
            # fallback: mark all as False
            live_status = {s: False for s in subdomains}

    nuclei_grouped = _group_findings_by_severity(nuclei_findings)
    nuclei_count = sum(len(items) for items in nuclei_grouped.values())
    interesting = _interesting_parameters(parameters)
    parameter_intelligence = _parameter_intelligence(parameters, discovered_parameters)
    screenshots_status = (
        f"Skipped ({screenshots_skipped_reason})"
        if screenshots_skipped_reason
        else ("Completed" if isinstance(screenshot_state, dict) and screenshot_state.get("status") == "completed" and not screenshots else (len(screenshots) if screenshots_available else "Not Run"))
    )
    nuclei_status = (
        f"{nuclei_status_label} ({nuclei_skipped_reason})"
        if nuclei_skipped_reason
        else ("Zero Findings" if isinstance(nuclei_state, dict) and nuclei_state.get("status") == "completed" and nuclei_count == 0 else (nuclei_count if nuclei_available else "Not Run"))
    )
    parameters_status = f"Skipped ({parameters_skipped_reason})" if parameters_skipped_reason else len(parameters)

    context = {
        "target": target,
        "version": __version__,
        "report_version": str(scan_state.get("report_version") or REPORT_VERSION),
        "framework_version": str(scan_state.get("framework_version") or __version__),
        "scan_profile": str(scan_state.get("scan_profile") or "balanced").title(),
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "subdomains": subdomains,
        "subdomain_sources": subdomain_sources,
        "alive_hosts": alive_hosts,
        "alive_hostnames": alive_hostnames,
        "alive_count": len(alive_hosts),
        "screenshots_count": len(screenshots),
        "screenshots_available": screenshots_available,
        "screenshots_skipped_reason": screenshots_skipped_reason,
        "screenshots_status": screenshots_status,
        "live_status": live_status,
        "parameters": parameters,
        "discovered_parameters": discovered_parameters,
        "parameter_intelligence": parameter_intelligence,
        "parameters_status": parameters_status,
        "parameters_skipped_reason": parameters_skipped_reason,
        "js_files": js_files,
        "endpoints": endpoints,
        "secrets": secrets,
        "interesting_parameters": interesting,
        "screenshots": screenshots,
        "screenshot_failures": screenshot_failures,
        "nuclei": nuclei_grouped,
        "nuclei_metadata": nuclei_metadata,
        "infrastructure": infrastructure if isinstance(infrastructure, dict) else {},
        "cloud_assets": cloud_assets if isinstance(cloud_assets, list) else [],
        "historical_dns": historical_dns if isinstance(historical_dns, dict) else {},
        "risk_score": risk_score if isinstance(risk_score, dict) else {},
        "template_intelligence": template_intelligence if isinstance(template_intelligence, dict) else {},
        "intelligence_attack_surface": intelligence_attack_surface if isinstance(intelligence_attack_surface, dict) else {},
        "historical_urls": historical_metadata,
        "historical_endpoints": historical_endpoints,
        "historical_diff": historical_diff if isinstance(historical_diff, dict) else {},
        "content_discovery": content_discovery,
        "security_header_assets": security_header_assets if isinstance(security_header_assets, dict) else {},
        "historical_js": historical_js,
        "asset_priority": asset_priority if isinstance(asset_priority, dict) else {},
        "next_investigation_targets": next_targets,
        "advanced_metadata": advanced_metadata if isinstance(advanced_metadata, dict) else {},
        "nuclei_count": nuclei_count,
        "nuclei_available": nuclei_available,
        "nuclei_skipped_reason": nuclei_skipped_reason,
        "nuclei_status_label": nuclei_status_label,
        "nuclei_status": nuclei_status,
        "nuclei_severity_counts": {sev: len(nuclei_grouped.get(sev, [])) for sev in ("critical", "high", "medium", "low", "info", "unknown")},
        "scan_duration": scan_duration or scan_meta.get("duration_human", "Not recorded"),
        "performance": performance,
        "report_logo_data_uri": _asset_data_uri(PACKAGE_ASSET_DIR / "report-logo.png") or _asset_data_uri(PROJECT_ROOT / "assets" / "report-logo.png"),
        "probe_results": probe_results,
        "technology_results": technology_results,
        "attack_surface": _attack_surface(probe_results, subdomains, alive_hosts, technology_results),
        "dependencies": [check.as_dict() for check in dependency_health(output=output)],
    }

    reports_dir = target_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    out_md = reports_dir / "report.md"
    out_html = reports_dir / "report.html"

    # Render
    with Progress(SpinnerColumn("line"), TextColumn("{task.description}"), transient=True, refresh_per_second=4) as progress:
        t = progress.add_task("Rendering report...", start=False)
        progress.start_task(t)
        try:
            _render_markdown(context, out_md)
            _render_html(context, out_html)
            progress.update(t, description="done")
        except Exception as exc:
            log.exception("Failed to render report")
            warn(f"Failed to render report: {exc}")
            return

    display_dir = _display_path(reports_dir)
    print_module_summary(
        "Report Generated",
        {
            "Target": target,
            "Duration": f"{time.perf_counter() - started:.2f}s",
            "Findings": context["nuclei_status"],
            "Screenshots": context["screenshots_status"],
            "Output Directory": display_dir,
            "Files": "report.md\nreport.html",
        },
    )
    success("Interactive report ready.")
    log.info("Report generated: %s and %s", out_md, out_html)


if __name__ == "__main__":
    run("example.com")
