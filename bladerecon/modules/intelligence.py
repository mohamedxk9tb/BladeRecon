"""Recon intelligence layer for BladeRecon.

This module turns existing scan artifacts into higher-value context: technology
stack, infrastructure hints, cloud references, risk scoring, attack-surface
mapping, and Nuclei template recommendations.
"""
from __future__ import annotations

import json
import re
import socket
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .utils import ModuleResult, clear_module_output, load_scan_state, nuclei_template_status, prepare_module_output, print_module_summary, setup_logging, skipped_result, success, target_output_dir, warn, write_json


TECH_PATTERNS: Dict[str, List[str]] = {
    "Apache": ["apache"],
    "Nginx": ["nginx"],
    "IIS": ["microsoft-iis", "iis"],
    "LiteSpeed": ["litespeed"],
    "PHP": ["php", "phpsessid", ".php"],
    "ASP.NET": ["asp.net", "x-aspnet", ".aspx"],
    "Java": ["jsessionid", "java", "spring"],
    "Node.js": ["node.js", "express", "x-powered-by: express"],
    "Python": ["django", "flask", "python", "wsgi"],
    "Laravel": ["laravel", "laravel_session"],
    "WordPress": ["wordpress", "wp-content", "wp-includes"],
    "Drupal": ["drupal"],
    "Joomla": ["joomla"],
    "React": ["react", "data-reactroot", "__react"],
    "Vue": ["vue", "__vue__", "data-v-"],
    "Angular": ["angular", "ng-version"],
    "Next.js": ["next.js", "__next", "_next/"],
}

TEMPLATE_TAGS: Dict[str, List[str]] = {
    "Apache": ["apache"],
    "Nginx": ["nginx"],
    "IIS": ["iis"],
    "LiteSpeed": ["litespeed"],
    "PHP": ["php"],
    "ASP.NET": ["asp", "aspnet", "iis"],
    "Java": ["java", "spring"],
    "Node.js": ["nodejs", "express"],
    "Python": ["django", "flask"],
    "Laravel": ["laravel", "php"],
    "WordPress": ["wordpress"],
    "Drupal": ["drupal"],
    "Joomla": ["joomla"],
    "React": ["react"],
    "Vue": ["vue"],
    "Angular": ["angular"],
    "Next.js": ["nextjs"],
}

STRONG_TEMPLATE_TECH = {"WordPress", "Drupal", "Joomla", "Laravel"}
SERVER_TEMPLATE_TECH = {"Apache", "Nginx", "IIS", "LiteSpeed", "PHP", "ASP.NET", "Java", "Node.js", "Python"}
WEAK_TEMPLATE_TECH = {"React", "Vue", "Angular", "Next.js"}
FRONTEND_FRAMEWORK_TECH = {"React", "Vue", "Angular", "Next.js"}
MIN_TEMPLATE_TAG_SCORE = 70

CLOUD_PATTERNS: Dict[str, List[str]] = {
    "AWS S3": [r"[a-z0-9.-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com", r"s3://[a-z0-9.\-_]+"],
    "AWS CloudFront": [r"[a-z0-9]+\.cloudfront\.net"],
    "Azure Blob Storage": [r"[a-z0-9-]+\.blob\.core\.windows\.net"],
    "Azure Functions": [r"[a-z0-9-]+\.azurewebsites\.net"],
    "Google Cloud Storage": [r"storage\.googleapis\.com/[a-z0-9.\-_]+", r"[a-z0-9.\-_]+\.storage\.googleapis\.com"],
    "Google Cloud Run": [r"[a-z0-9-]+-[a-z0-9-]+\.a\.run\.app"],
}


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return default


def _read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def _host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return (parsed.hostname or value).lower()


def _resolve_ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ""


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _flatten_strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for item in value.values():
            yield from _flatten_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _flatten_strings(item)
    elif value is not None:
        yield str(value)


def _detect_from_text(text: str) -> Set[str]:
    haystack = text.lower()
    detected = set()
    for name, needles in TECH_PATTERNS.items():
        if any(needle in haystack for needle in needles):
            detected.add(name)
    return detected


def _load_scan_data(target_dir: Path) -> Dict[str, Any]:
    return {
        "subdomains": _read_lines(target_dir / "subdomains" / "subdomains.txt"),
        "subdomain_rows": _read_json(target_dir / "subdomains" / "subdomains.json", []),
        "probe_rows": _read_json(target_dir / "probe" / "probe.json", []),
        "technology_rows": _read_json(target_dir / "technologies" / "technologies.json", []),
        "alive_hosts": _read_lines(target_dir / "probe" / "alive.txt"),
        "js_rows": _read_json(target_dir / "js" / "js_files.json", []),
        "endpoint_rows": _read_json(target_dir / "endpoints" / "endpoints.json", []),
        "secret_rows": _read_json(target_dir / "secrets" / "secrets.json", []),
        "parameters": _read_lines(target_dir / "parameters" / "parameters.txt"),
        "nuclei_rows": _read_json(target_dir / "nuclei" / "results.json", []),
    }


def _has_valid_scan_context(target: str, output: Path, target_dir: Path) -> bool:
    state = load_scan_state(target, output)
    modules = state.get("modules", {}) if isinstance(state, dict) else {}
    if isinstance(modules, dict) and any(isinstance(row, dict) and row.get("status") in {"completed", "skipped", "failed"} for row in modules.values()):
        return True
    artifacts = [
        target_dir / "subdomains" / "subdomains.txt",
        target_dir / "probe" / "alive.txt",
        target_dir / "probe" / "probe.json",
        target_dir / "js" / "js_files.json",
        target_dir / "endpoints" / "endpoints.json",
        target_dir / "secrets" / "secrets.json",
        target_dir / "parameters" / "parameters.txt",
        target_dir / "nuclei" / "results.json",
        target_dir / "nuclei" / "results.jsonl",
    ]
    for path in artifacts:
        try:
            if path.exists() and path.read_text(encoding="utf-8-sig").strip():
                return True
        except Exception:
            continue
    return False


def detect_technologies(scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    records: Dict[str, Dict[str, Any]] = {}

    def confidence_rank(value: str) -> int:
        return {"low": 1, "medium": 2, "high": 3}.get(str(value or "").strip().lower(), 0)

    def frontend_confidence(name: str, source: str, confidence: str, evidence: str = "") -> str:
        if name not in FRONTEND_FRAMEWORK_TECH:
            return confidence
        source_l = source.lower()
        evidence_l = evidence.lower()
        strong_markers = ("data-reactroot", "__react", "ng-version", "__vue__", "data-v-", "__next", "_next/")
        if any(marker in evidence_l for marker in strong_markers) and ("fingerprint" in source_l or "artifact" in source_l):
            return confidence
        if source_l in {"js-asset", "endpoint"} or "title" in source_l:
            return "Medium" if source_l == "js-asset" else "Low"
        return "Medium" if str(confidence).strip().lower() == "high" else confidence

    def add(name: str, source: str, host: str = "", confidence: str = "Medium", evidence: str = "") -> None:
        if not name:
            return
        confidence = frontend_confidence(name, source, confidence, evidence)
        row = records.setdefault(name, {"name": name, "sources": set(), "hosts": set(), "confidence": "Medium", "evidence": set()})
        row["sources"].add(source)
        if host:
            row["hosts"].add(host)
        if evidence:
            row["evidence"].add(evidence[:180])
        if confidence_rank(confidence) > confidence_rank(row.get("confidence", "")):
            row["confidence"] = confidence.title()

    for row in scan_data.get("technology_rows", []) or []:
        if not isinstance(row, dict):
            continue
        host = _host(str(row.get("host") or row.get("url") or ""))
        details = row.get("technologies", []) if isinstance(row.get("technologies"), list) else []
        for detail in details:
            if not isinstance(detail, dict):
                continue
            sources = detail.get("sources") if isinstance(detail.get("sources"), list) else ["Technology Artifact"]
            evidence = detail.get("evidence") if isinstance(detail.get("evidence"), list) else []
            add(
                str(detail.get("name") or ""),
                ", ".join(str(source) for source in sources if source) or "Technology Artifact",
                host,
                str(detail.get("confidence") or "Medium"),
                "; ".join(str(item) for item in evidence if item),
            )
        if not details:
            for tech in row.get("detected", []) or []:
                add(str(tech), "Technology Artifact", host, "Medium")

    for row in scan_data.get("probe_rows", []) or []:
        if not isinstance(row, dict):
            continue
        host = _host(str(row.get("final_url") or row.get("url") or ""))
        for detail in row.get("technology_details", []) or []:
            if not isinstance(detail, dict):
                continue
            sources = detail.get("sources") if isinstance(detail.get("sources"), list) else ["Probe Fingerprint"]
            evidence = detail.get("evidence") if isinstance(detail.get("evidence"), list) else []
            add(
                str(detail.get("name") or ""),
                ", ".join(str(source) for source in sources if source) or "Probe Fingerprint",
                host,
                str(detail.get("confidence") or "Medium"),
                "; ".join(str(item) for item in evidence if item),
            )
        for tech in row.get("technologies", []) or []:
            add(str(tech), "probe-fingerprint", host, "Medium")
        for key in ("server", "cdn", "waf", "title"):
            for tech in _detect_from_text(str(row.get(key) or "")):
                add(tech, "probe-header" if key in {"server", "cdn", "waf"} else "html-title", host, "High" if key in {"server", "cdn", "waf"} else "Medium", str(row.get(key) or "")[:120])

    for row in scan_data.get("js_rows", []) or []:
        for tech in _detect_from_text(" ".join(_flatten_strings(row))):
            add(tech, "js-asset", confidence="High", evidence=str(row.get("url") if isinstance(row, dict) else "")[:120])

    for row in scan_data.get("endpoint_rows", []) or []:
        for tech in _detect_from_text(" ".join(_flatten_strings(row))):
            add(tech, "endpoint", confidence="Low")

    output = []
    for row in records.values():
        output.append(
            {
                "name": row["name"],
                "confidence": row["confidence"],
                "sources": sorted(row["sources"]),
                "hosts": sorted(row["hosts"]),
                "evidence": sorted(row["evidence"]),
            }
        )
    return sorted(output, key=lambda item: item["name"].lower())


def collect_infrastructure(target: str, scan_data: Dict[str, Any]) -> Dict[str, Any]:
    hosts = sorted({_host(target), *[_host(url) for url in scan_data.get("alive_hosts", [])]})
    assets = []
    providers = set()
    for row in scan_data.get("probe_rows", []) or []:
        if isinstance(row, dict):
            for key in ("cdn", "waf", "server"):
                value = str(row.get(key) or "").strip()
                if value:
                    providers.add(value.split("/")[0])
    for host in hosts:
        ip = _resolve_ip(host)
        assets.append(
            {
                "host": host,
                "ip": ip,
                "reverse_dns": _reverse_dns(ip) if ip else "",
                "asn": "",
                "organization": ", ".join(sorted(providers)) if providers else "",
                "provider": ", ".join(sorted(providers)) if providers else "",
                "country": "",
                "cidr": f"{ip}/32" if ip else "",
            }
        )
    return {"assets": assets, "providers": sorted(providers), "primary_ip": assets[0]["ip"] if assets else ""}


def discover_cloud_assets(scan_data: Dict[str, Any]) -> List[Dict[str, str]]:
    text = "\n".join(_flatten_strings(scan_data))
    assets: List[Dict[str, str]] = []
    seen = set()
    for provider, patterns in CLOUD_PATTERNS.items():
        for pattern in patterns:
            for match in re.findall(pattern, text, flags=re.IGNORECASE):
                value = match if isinstance(match, str) else match[0]
                key = (provider, value.lower())
                if key in seen:
                    continue
                seen.add(key)
                assets.append({"type": provider, "value": value, "source": "scan-artifacts"})
    return sorted(assets, key=lambda item: (item["type"], item["value"]))


def build_historical_dns(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    rows = scan_data.get("subdomain_rows", []) or []
    hosts = []
    for row in rows:
        if isinstance(row, dict):
            hosts.append({"host": row.get("subdomain", ""), "sources": row.get("sources", row.get("source", []))})
    return {
        "historical_subdomains": hosts,
        "historical_hosts": sorted({str(item.get("host") or "") for item in hosts if item.get("host")}),
        "historical_a_records": [],
    }


def calculate_risk(scan_data: Dict[str, Any], technologies: List[Dict[str, Any]], cloud_assets: List[Dict[str, str]]) -> Dict[str, Any]:
    score = 0
    factors = []
    endpoint_text = "\n".join(_flatten_strings(scan_data.get("endpoint_rows", []))).lower()
    if any(token in endpoint_text for token in ("admin", "dashboard", "login", "wp-admin")):
        score += 20
        factors.append("Admin or login surface observed")
    if scan_data.get("secret_rows"):
        score += min(25, 8 * len(scan_data["secret_rows"]))
        factors.append("Secret patterns detected")
    if cloud_assets:
        score += min(15, 5 * len(cloud_assets))
        factors.append("Cloud assets referenced")
    if scan_data.get("nuclei_rows"):
        score += min(35, 10 * len(scan_data["nuclei_rows"]))
        factors.append("Nuclei findings present")
    tech_names = {item["name"] for item in technologies}
    if tech_names.intersection({"WordPress", "Drupal", "Joomla", "Laravel"}):
        score += 10
        factors.append("High-interest web framework or CMS detected")
    if len(scan_data.get("parameters", [])) >= 50:
        score += 10
        factors.append("Large parameter surface")
    score = min(100, score)
    level = "High" if score >= 70 else "Medium" if score >= 40 else "Low"
    return {"score": score, "level": level, "factors": factors}


def _confidence_score(value: str) -> int:
    return {"high": 80, "medium": 50, "low": 25}.get(str(value or "").strip().lower(), 0)


def _template_tag_score(tech: Dict[str, Any], total_hosts: int) -> Tuple[int, str]:
    name = str(tech.get("name") or "")
    confidence = str(tech.get("confidence") or "Medium")
    hosts = tech.get("hosts") if isinstance(tech.get("hosts"), list) else []
    host_count = len([host for host in hosts if str(host).strip()])
    score = _confidence_score(confidence)
    reason = f"{confidence} confidence"

    if name in STRONG_TEMPLATE_TECH:
        score += 20
        reason += "; strong CMS/framework mapping"
    elif name in SERVER_TEMPLATE_TECH:
        score += 5
        reason += "; server/framework mapping"
        if 0 < total_hosts <= 3 and host_count == total_hosts:
            score += 15
            reason += "; covers all observed hosts"
        if host_count <= 1 and total_hosts >= 20:
            score -= 25
            reason += "; low host coverage"
    elif name in WEAK_TEMPLATE_TECH:
        score -= 45
        reason += "; weak client-side framework mapping"
    else:
        score -= 20
        reason += "; generic technology"

    if host_count >= 3:
        score += 10
        reason += f"; observed on {host_count} hosts"
    elif host_count:
        reason += f"; observed on {host_count} host"

    return max(0, min(100, score)), reason


def recommend_templates(technologies: List[Dict[str, Any]], cloud_assets: List[Dict[str, str]]) -> Dict[str, Any]:
    selected: Dict[str, List[str]] = {}
    scored: List[Dict[str, Any]] = []
    observed_hosts: Set[str] = set()
    for tech in technologies:
        hosts = tech.get("hosts") if isinstance(tech.get("hosts"), list) else []
        observed_hosts.update(str(host).strip().lower() for host in hosts if str(host).strip())
    total_hosts = len(observed_hosts)
    for tech in technologies:
        name = str(tech.get("name") or "")
        tags = TEMPLATE_TAGS.get(name, [])
        if not tags:
            continue
        score, reason = _template_tag_score(tech, total_hosts)
        accepted = score >= MIN_TEMPLATE_TAG_SCORE
        scored.append(
            {
                "technology": name,
                "tags": tags,
                "score": score,
                "accepted": accepted,
                "reason": reason,
            }
        )
        if accepted:
            selected[name] = tags
    if cloud_assets:
        selected["Cloud Assets"] = ["cloud", "exposure", "misconfig"]
        scored.append(
            {
                "technology": "Cloud Assets",
                "tags": ["cloud", "exposure", "misconfig"],
                "score": 85,
                "accepted": True,
                "reason": "Cloud storage/service reference observed",
            }
        )
    selected_tags = sorted({tag for tags in selected.values() for tag in tags})
    skipped = sorted({tag for tags in TEMPLATE_TAGS.values() for tag in tags if tag not in selected_tags})
    status = nuclei_template_status()
    return {
        "templates_available": status.get("template_count", 0),
        "selected_tags": selected_tags,
        "selected": [{"reason": reason, "tags": tags} for reason, tags in sorted(selected.items())],
        "scored_tags": sorted(scored, key=lambda item: (-int(item["score"]), str(item["technology"]).lower())),
        "minimum_score": MIN_TEMPLATE_TAG_SCORE,
        "skipped_tags": skipped,
        "skipped_reason": "No high-confidence matching fingerprint" if not selected_tags else "Low-confidence mappings excluded" if skipped else "",
    }


def build_attack_surface(target: str, scan_data: Dict[str, Any], technologies: List[Dict[str, Any]], infrastructure: Dict[str, Any], cloud_assets: List[Dict[str, str]], risk: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "target": target,
        "subdomains": scan_data.get("subdomains", []),
        "alive_hosts": scan_data.get("alive_hosts", []),
        "technologies": technologies,
        "endpoints": scan_data.get("endpoint_rows", []),
        "parameters": scan_data.get("parameters", []),
        "secrets": scan_data.get("secret_rows", []),
        "cloud_assets": cloud_assets,
        "infrastructure": infrastructure,
        "findings": scan_data.get("nuclei_rows", []),
        "risk": risk,
    }


def _write_text(path: Path, lines: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).strip() + ("\n" if lines else ""), encoding="utf-8")


def run(target: str, output: Path = Path("results"), resume: bool = False) -> ModuleResult:
    target_dir = target_output_dir(output, target)
    log = setup_logging(target, output, "intelligence")
    started = time.perf_counter()
    if not resume:
        clear_module_output(output, target, "intelligence")
        clear_module_output(output, target, "technology")
    if not target_dir.exists() or not _has_valid_scan_context(target, output, target_dir):
        warn(f"No valid scan found for target: {target}")
        log.warning("Intelligence skipped: no scan_state or valid scan artifacts")
        return skipped_result("No valid scan found")

    scan_data = _load_scan_data(target_dir)
    technologies = detect_technologies(scan_data)
    infrastructure = collect_infrastructure(target, scan_data)
    cloud_assets = discover_cloud_assets(scan_data)
    historical_dns = build_historical_dns(scan_data)
    risk = calculate_risk(scan_data, technologies, cloud_assets)
    template_intel = recommend_templates(technologies, cloud_assets)
    attack_surface = build_attack_surface(target, scan_data, technologies, infrastructure, cloud_assets, risk)

    technology_dir = prepare_module_output(output, target, "technology", resume=resume)
    write_json(technology_dir / "technology.json", technologies)
    _write_text(
        technology_dir / "technology.txt",
        [
            f"{item['name']} ({item['confidence']}) - {', '.join(item['sources'])}"
            + (f" | Evidence: {'; '.join(item.get('evidence', [])[:2])}" if item.get("evidence") else "")
            for item in technologies
        ],
    )

    intel_dir = prepare_module_output(output, target, "intelligence", resume=resume)
    write_json(intel_dir / "infrastructure.json", infrastructure)
    write_json(intel_dir / "infrastructure_assets.json", {"shared_ip_assets": [], "reverse_dns": infrastructure.get("assets", []), "related_hosts": scan_data.get("subdomains", [])})
    write_json(intel_dir / "historical_dns.json", historical_dns)
    write_json(intel_dir / "cloud_assets.json", cloud_assets)
    write_json(intel_dir / "risk_score.json", risk)
    write_json(intel_dir / "template_intelligence.json", template_intel)
    write_json(intel_dir / "attack_surface.json", attack_surface)

    duration = time.perf_counter() - started
    print_module_summary(
        "Intelligence Summary",
        {
            "Target": target,
            "Duration": f"{duration:.2f}s",
            "Technologies": len(technologies),
            "Infrastructure Assets": len(infrastructure.get("assets", [])),
            "Cloud Assets": len(cloud_assets),
            "Risk Score": f"{risk['score']}/100 ({risk['level']})",
            "Template Tags": ", ".join(template_intel.get("selected_tags", [])) or "Not Run",
            "Output Location": intel_dir,
        },
    )
    log.info("Intelligence generated in %.2fs", duration)
    success("Intelligence layer generated")
    return ModuleResult()
