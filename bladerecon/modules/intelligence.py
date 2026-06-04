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
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from .utils import ModuleResult, atomic_write_text, clear_module_output, load_scan_state, nuclei_template_status, prepare_module_output, print_module_summary, setup_logging, skipped_result, success, target_output_dir, warn, write_json


TECH_PATTERNS: Dict[str, List[str]] = {
    "Apache": ["apache"],
    "Nginx": ["nginx"],
    "IIS": ["microsoft-iis"],
    "LiteSpeed": ["litespeed"],
    "PHP": ["php", "phpsessid", ".php"],
    "ASP.NET": ["asp.net", "x-aspnet", ".aspx"],
    "Java": ["jsessionid", "spring"],
    "Node.js": ["node.js", "express", "x-powered-by: express"],
    "Python": ["django", "flask", "python", "wsgi"],
    "Laravel": ["laravel_session"],
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
MIN_TEMPLATE_TAG_SCORE = 80

CLOUD_PATTERNS: Dict[str, List[str]] = {
    "AWS S3": [r"[a-z0-9.-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com", r"s3://[a-z0-9.\-_]+"],
    "AWS CloudFront": [r"[a-z0-9]+\.cloudfront\.net"],
    "Azure Blob Storage": [r"[a-z0-9-]+\.blob\.core\.windows\.net"],
    "Azure Functions": [r"[a-z0-9-]+\.azurewebsites\.net"],
    "Google Cloud Storage": [r"storage\.googleapis\.com/[a-z0-9.\-_]+", r"[a-z0-9.\-_]+\.storage\.googleapis\.com"],
    "Google Cloud Run": [r"[a-z0-9-]+-[a-z0-9-]+\.a\.run\.app"],
}

NOISY_INFRASTRUCTURE_TOKENS = {
    "akamai",
    "cloudflare",
    "cloudfront",
    "fastly",
    "cdn",
}

HIGH_VALUE_ENDPOINT_TOKENS = (
    "admin",
    "auth",
    "login",
    "graphql",
    "swagger",
    "openapi",
    "/api",
    "debug",
    "internal",
)

AUTH_TOKENS = ("login", "signin", "auth", "account")
API_TOKENS = ("api", "graphql", "openapi", "swagger")
ADMIN_TOKENS = ("admin", "dashboard", "manage", "console")
DEBUG_TOKENS = ("debug", "trace", "metrics", "actuator", "health")
PARAMETER_RISK_TOKENS = ("redirect", "return", "next", "url", "file", "path", "id")

TESTING_DIRECTIONS: Dict[str, str] = {
    "Authentication": "Session handling, OAuth flow review, password reset, authorization bypass testing",
    "GraphQL": "Introspection, field suggestions, batching, object-level authorization testing",
    "API": "Endpoint authorization, object ID tampering, mass assignment, rate-limit testing",
    "Admin": "Access control, default credential checks, unauthenticated sub-path review",
    "Debug": "Information disclosure, environment leakage, stack traces, internal service exposure",
    "Historical": "Legacy authorization checks, deprecated parameter handling, forgotten API behavior",
    "Parameters": "Open redirect, file/path traversal, IDOR, parameter pollution testing",
}


@dataclass
class OpportunityEvidence:
    type: str
    value: str
    score: int
    reason: str
    source: str = "artifact"


@dataclass
class HostOpportunity:
    host: str
    score: int = 0
    opportunity_types: Set[str] = field(default_factory=set)
    evidence: List[OpportunityEvidence] = field(default_factory=list)
    noise_penalty: int = 0

    def add(self, opportunity_type: str, value: str, score: int, reason: str, source: str = "artifact") -> None:
        self.opportunity_types.add(opportunity_type)
        self.evidence.append(OpportunityEvidence(opportunity_type, value, score, reason, source))
        self.score += score

    def to_report_row(self) -> Dict[str, Any]:
        strongest = sorted(self.evidence, key=lambda item: (-item.score, item.type, item.value))[:5]
        opportunity = _primary_opportunity_type(self.opportunity_types)
        indicator_count = len({item.value.lower() for item in self.evidence if item.value})
        evidence_diversity = len({item.source for item in self.evidence if item.source})
        correlation_strength = _correlation_strength(self)
        confidence = _opportunity_confidence(indicator_count, evidence_diversity, correlation_strength)
        confidence = _cap_historical_only_confidence(self, confidence)
        score_cap = _confidence_score_cap(confidence)
        if _historical_only_opportunity(self):
            score_cap = min(score_cap, 60)
        capped_score = min(self.score + correlation_strength * 8, score_cap)
        adjusted_score = max(0, min(100, capped_score - self.noise_penalty))
        priority = "Critical Investigation" if adjusted_score >= 85 else "High Investigation" if adjusted_score >= 65 else "Focused Review"
        return {
            "host": self.host,
            "opportunity_type": opportunity,
            "opportunity_types": sorted(self.opportunity_types),
            "score": adjusted_score,
            "priority": priority,
            "confidence": confidence,
            "indicator_count": indicator_count,
            "evidence_diversity": evidence_diversity,
            "correlation_strength": correlation_strength,
            "evidence_summary": _evidence_summary(self, strongest),
            "evidence": [asdict(item) for item in strongest],
            "priority_reason": _priority_reason(self, strongest),
            "suggested_testing": _suggested_testing(self.opportunity_types),
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
        "content_discovery_rows": _read_json(target_dir / "content_discovery" / "interesting_paths.json", []),
        "historical_endpoints": _read_json(target_dir / "historical" / "endpoints.json", []),
        "historical_diff": _read_json(target_dir / "historical_diff.json", {}),
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
        row = records.setdefault(name, {"name": name, "sources": set(), "hosts": set(), "confidence": confidence.title(), "evidence": set()})
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
                add(str(tech), "Technology Artifact", host, "Low")

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
            add(str(tech), "probe-fingerprint", host, "Low")
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
    probe_ips: Dict[str, str] = {}
    for row in scan_data.get("probe_rows", []) or []:
        if isinstance(row, dict):
            host = _host(str(row.get("final_url") or row.get("url") or row.get("host") or ""))
            ip = str(row.get("ip") or row.get("address") or row.get("a_record") or "").strip()
            if host and ip:
                probe_ips[host] = ip
            for key in ("cdn", "waf", "server"):
                value = str(row.get(key) or "").strip()
                if value:
                    providers.add(value.split("/")[0])
    for host in hosts:
        ip = probe_ips.get(host, "")
        assets.append(
            {
                "host": host,
                "ip": ip,
                "reverse_dns": "",
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


def _nuclei_severity(finding: Dict[str, Any]) -> str:
    info = finding.get("info") if isinstance(finding.get("info"), dict) else {}
    return str(info.get("severity") or finding.get("severity") or "unknown").lower()


def _noise_assessment(scan_data: Dict[str, Any], infrastructure: Dict[str, Any], cloud_assets: List[Dict[str, str]]) -> Dict[str, Any]:
    probe_rows = scan_data.get("probe_rows", []) if isinstance(scan_data.get("probe_rows"), list) else []
    alive_count = len(scan_data.get("alive_hosts", []) or [])
    noisy_hosts: Set[str] = set()
    providers: Set[str] = set()
    for row in probe_rows:
        if not isinstance(row, dict):
            continue
        host = _host(str(row.get("final_url") or row.get("url") or ""))
        text = " ".join(str(row.get(key) or "") for key in ("cdn", "waf", "server")).lower()
        if any(token in text for token in NOISY_INFRASTRUCTURE_TOKENS):
            noisy_hosts.add(host)
            providers.update(token for token in NOISY_INFRASTRUCTURE_TOKENS if token in text)
    infra_assets = infrastructure.get("assets", []) if isinstance(infrastructure.get("assets"), list) else []
    for item in infra_assets:
        if not isinstance(item, dict):
            continue
        text = " ".join(str(item.get(key) or "") for key in ("organization", "provider", "reverse_dns")).lower()
        if any(token in text for token in NOISY_INFRASTRUCTURE_TOKENS):
            host = str(item.get("host") or "")
            if host:
                noisy_hosts.add(host)
            providers.update(token for token in NOISY_INFRASTRUCTURE_TOKENS if token in text)
    ratio = round(len(noisy_hosts) / max(1, alive_count), 4)
    return {
        "alive_hosts": alive_count,
        "noisy_infrastructure_hosts": len(noisy_hosts),
        "noisy_infrastructure_ratio": ratio,
        "dominant_noise_sources": sorted(providers),
        "cloud_asset_references": len(cloud_assets),
        "assessment": "CDN/WAF-heavy results; prioritize app-owned APIs, auth, admin, secrets, and verified findings" if ratio >= 0.5 else "No dominant CDN/WAF noise detected",
    }


def build_investigation_priorities(scan_data: Dict[str, Any], risk: Dict[str, Any]) -> List[Dict[str, Any]]:
    priorities: List[Dict[str, Any]] = []

    def add(target: str, source: str, score: int, reason: str) -> None:
        value = str(target or "").strip()
        if not value:
            return
        priorities.append({"target": value, "source": source, "score": max(0, min(100, score)), "reason": reason})

    for row in scan_data.get("nuclei_rows", []) or []:
        if not isinstance(row, dict):
            continue
        severity = _nuclei_severity(row)
        if severity in {"critical", "high", "medium"}:
            add(str(row.get("host") or row.get("matched") or ""), "nuclei", {"critical": 100, "high": 90, "medium": 70}.get(severity, 60), f"{severity.title()} Nuclei finding")
    for row in scan_data.get("secret_rows", []) or []:
        if isinstance(row, dict):
            add(str(row.get("source") or row.get("url") or row.get("file") or ""), "secrets", 85, f"Potential secret: {row.get('type', 'secret')}")
    for row in scan_data.get("endpoint_rows", []) or []:
        endpoint = str(row.get("endpoint") if isinstance(row, dict) else "")
        lower = endpoint.lower()
        if any(token in lower for token in HIGH_VALUE_ENDPOINT_TOKENS):
            add(endpoint, "endpoints", 75 if any(token in lower for token in ("admin", "graphql", "swagger", "openapi", "debug", "internal")) else 60, "High-interest endpoint keyword")
    for param in scan_data.get("parameters", []) or []:
        lower = str(param).lower()
        if any(token in lower for token in ("token", "auth", "redirect", "callback", "url", "next", "return", "api_key", "secret")):
            add(str(param), "parameters", 55, "High-value parameter candidate")

    deduped: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in priorities:
        key = (str(item["target"]).lower(), str(item["source"]))
        existing = deduped.get(key)
        if not existing or int(item["score"]) > int(existing["score"]):
            deduped[key] = item
    ranked = sorted(deduped.values(), key=lambda item: (-int(item["score"]), str(item["target"]).lower()))
    if not ranked and risk.get("factors"):
        add("Review risk factors", "risk", int(risk.get("score") or 0), "; ".join(str(item) for item in risk.get("factors", [])[:3]))
        ranked = priorities
    return ranked[:15]


def _host_opportunity(rows: Dict[str, HostOpportunity], value: str) -> HostOpportunity:
    host = _host(value)
    return rows.setdefault(host, HostOpportunity(host=host))


def _value_contains(value: str, tokens: Tuple[str, ...]) -> bool:
    lower = value.lower()
    return any(token in lower for token in tokens)


def _parameter_tokens(parameters: Iterable[str]) -> List[str]:
    found = []
    for parameter in parameters:
        value = str(parameter or "").strip()
        lower = value.lower()
        if any(token == lower or token in lower for token in PARAMETER_RISK_TOKENS):
            found.append(value)
    return sorted(set(found), key=str.lower)


def _host_risky_parameters(scan_data: Dict[str, Any]) -> Dict[str, List[str]]:
    host_params: Dict[str, Set[str]] = {}

    def add_from_url(value: str) -> None:
        raw = str(value or "").strip()
        if not raw or raw.startswith("/"):
            return
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or not parsed.query:
            return
        risky = _parameter_tokens(parse_qs(parsed.query).keys())
        if risky:
            host_params.setdefault(host, set()).update(risky)

    row_sources = (
        "endpoint_rows",
        "historical_endpoints",
        "content_discovery_rows",
    )
    for source in row_sources:
        for row in scan_data.get(source, []) or []:
            if isinstance(row, dict):
                for key in ("endpoint", "url", "source", "final_url"):
                    add_from_url(str(row.get(key) or ""))
            else:
                add_from_url(str(row))

    historical_diff = scan_data.get("historical_diff", {}) if isinstance(scan_data.get("historical_diff"), dict) else {}
    for key in ("historical_and_currently_alive", "removed_apis", "legacy_paths", "potentially_forgotten_assets"):
        for value in historical_diff.get(key, []) if isinstance(historical_diff.get(key), list) else []:
            add_from_url(str(value))

    return {host: sorted(values, key=str.lower) for host, values in host_params.items()}


def _primary_opportunity_type(types: Set[str]) -> str:
    for value in ("GraphQL", "Admin", "Debug", "Historical", "API", "Authentication", "Parameters"):
        if value in types:
            return value
    return sorted(types)[0] if types else "Opportunity"


def _suggested_testing(types: Set[str]) -> str:
    ordered = ["GraphQL", "Admin", "Debug", "Historical", "API", "Authentication", "Parameters"]
    suggestions = [TESTING_DIRECTIONS[item] for item in ordered if item in types]
    return "; ".join(suggestions[:3]) if suggestions else "Manual verification of exposed surface and authorization behavior"


def _correlation_strength(opportunity: HostOpportunity) -> int:
    sources = {item.source for item in opportunity.evidence if item.source}
    types = opportunity.opportunity_types
    values = " ".join(item.value.lower() for item in opportunity.evidence)
    strength = 0
    if len(opportunity.evidence) >= 2:
        strength += 1
    if len(sources) >= 2:
        strength += 1
    if "GraphQL" in types:
        if "Authentication" in types:
            strength += 1
        if "Historical" in types and "graphql" in values:
            strength += 1
        if "Parameters" in types:
            strength += 1
    if "API" in types:
        if "Parameters" in types:
            strength += 1
        if "Historical" in types:
            strength += 1
        if len({match.group(0) for match in re.finditer(r"/v\d+", values)}) >= 2:
            strength += 1
    if "Admin" in types:
        if "Authentication" in types:
            strength += 1
        if "Historical" in types:
            strength += 1
        if "Debug" in types:
            strength += 1
    if "Historical" in types:
        if any(item.source == "historical_alive" for item in opportunity.evidence):
            strength += 1
        if any(item.source == "historical_removed" for item in opportunity.evidence):
            strength += 1
    return min(6, strength)


def _opportunity_confidence(indicator_count: int, evidence_diversity: int, correlation_strength: int) -> str:
    if correlation_strength >= 5 or (indicator_count >= 4 and evidence_diversity >= 3):
        return "Very High"
    if correlation_strength >= 3 or (indicator_count >= 3 and evidence_diversity >= 2):
        return "High"
    if correlation_strength >= 1 or evidence_diversity >= 2:
        return "Medium"
    return "Low"


def _cap_historical_only_confidence(opportunity: HostOpportunity, confidence: str) -> str:
    if _historical_only_opportunity(opportunity) and confidence in {"High", "Very High"}:
        return "Medium"
    return confidence


def _historical_only_opportunity(opportunity: HostOpportunity) -> bool:
    sources = {item.source for item in opportunity.evidence if item.source}
    if not sources:
        return False
    historical_sources = {"historical_endpoint", "historical_removed", "historical_legacy", "historical_alive", "historical_only"}
    evidence_sources = sources - {"correlation"}
    return bool(evidence_sources) and evidence_sources.issubset(historical_sources)


def _add_unique_signal(signals: List[str], value: str) -> None:
    if value and value not in signals:
        signals.append(value)


def _validation_strength(score: int) -> str:
    if score >= 6:
        return "Strong"
    if score >= 3:
        return "Moderate"
    if score >= 1:
        return "Weak"
    return "None"


def _opportunity_validation(opportunity: HostOpportunity, row: Dict[str, Any], scan_data: Dict[str, Any], noisy_hosts: Set[str]) -> Dict[str, Any]:
    host = opportunity.host
    types = opportunity.opportunity_types
    positive: List[str] = []
    negative: List[str] = []
    score = 0
    has_nuclei_match = False

    for finding in scan_data.get("nuclei_rows", []) or []:
        if not isinstance(finding, dict):
            continue
        finding_target = str(finding.get("host") or finding.get("matched") or finding.get("url") or "")
        if _host(finding_target) != host:
            continue
        has_nuclei_match = True
        severity = _nuclei_severity(finding)
        if severity in {"critical", "high"}:
            _add_unique_signal(positive, f"{severity.title()} Nuclei finding")
            score += 4
        elif severity == "medium":
            _add_unique_signal(positive, "Medium Nuclei finding")
            score += 2
        elif severity:
            _add_unique_signal(positive, "Nuclei finding present")
            score += 1

    if not has_nuclei_match:
        _add_unique_signal(negative, "No Nuclei validation findings for this host")

    for row_data in scan_data.get("probe_rows", []) or []:
        if not isinstance(row_data, dict):
            continue
        probe_host = _host(str(row_data.get("final_url") or row_data.get("url") or ""))
        if probe_host != host:
            continue
        text = " ".join(str(row_data.get(key) or "") for key in ("url", "final_url", "title", "server", "cdn", "waf")).lower()
        if row_data.get("alive") is False:
            _add_unique_signal(negative, "Probe marked service unreachable")
        if any(token in text for token in NOISY_INFRASTRUCTURE_TOKENS):
            _add_unique_signal(negative, "CDN/WAF infrastructure indicator observed")
        if _value_contains(text, AUTH_TOKENS):
            _add_unique_signal(positive, "Auth-related discovery confirmed by probe")
            score += 1

    for endpoint_row in scan_data.get("endpoint_rows", []) or []:
        endpoint = str(endpoint_row.get("endpoint") if isinstance(endpoint_row, dict) else endpoint_row)
        if not endpoint or _host(endpoint) != host:
            continue
        lower = endpoint.lower()
        category = str(endpoint_row.get("category") if isinstance(endpoint_row, dict) else "").lower()
        if "GraphQL" in types and "graphql" in lower:
            _add_unique_signal(positive, "GraphQL access observed in endpoint artifacts")
            score += 2 if "graphql" in category else 1
        if "API" in types and any(token in lower for token in ("swagger", "openapi", "/api", "/v1", "/v2", "/v3")):
            _add_unique_signal(positive, "API exposure confirmed by endpoint artifacts")
            score += 1
        if "Authentication" in types and _value_contains(lower, AUTH_TOKENS):
            _add_unique_signal(positive, "Auth-related endpoint discovered")
            score += 1

    for content_row in scan_data.get("content_discovery_rows", []) or []:
        if not isinstance(content_row, dict):
            continue
        url = str(content_row.get("url") or "")
        if not url or _host(url) != host:
            continue
        path = str(content_row.get("path") or urlparse(url).path).lower()
        status = int(content_row.get("status_code") or 0)
        if status in {200, 401, 403}:
            _add_unique_signal(positive, f"Interesting response pattern observed ({status})")
            score += 1
            if "GraphQL" in types and "graphql" in path:
                _add_unique_signal(positive, "GraphQL path returned actionable response")
                score += 2
            if "API" in types and ("swagger" in path or "openapi" in path):
                _add_unique_signal(positive, "OpenAPI/Swagger access confirmed")
                score += 2
        elif status in {0, 404, 410}:
            _add_unique_signal(negative, "Dead endpoint response observed")

    historical_diff = scan_data.get("historical_diff", {}) if isinstance(scan_data.get("historical_diff"), dict) else {}
    alive_historical_values = {
        str(value).strip().lower()
        for value in historical_diff.get("historical_and_currently_alive", [])
        if isinstance(historical_diff.get("historical_and_currently_alive"), list)
    }
    removed_historical_values = {
        str(value).strip().lower()
        for value in historical_diff.get("removed_apis", [])
        if isinstance(historical_diff.get("removed_apis"), list)
    }
    for value in historical_diff.get("historical_and_currently_alive", []) if isinstance(historical_diff.get("historical_and_currently_alive"), list) else []:
        if _host(str(value)) == host:
            _add_unique_signal(positive, "Historical endpoint host is alive")
            score += 1
    for key in ("removed_apis", "legacy_paths"):
        for value in historical_diff.get(key, []) if isinstance(historical_diff.get(key), list) else []:
            if str(value).strip().lower() in alive_historical_values:
                continue
            if key == "legacy_paths" and str(value).strip().lower() in removed_historical_values:
                continue
            if _host(str(value)) == host:
                _add_unique_signal(negative, "Historical-only or legacy path needs live verification")

    if int(row.get("indicator_count") or 0) <= 1 and int(row.get("evidence_diversity") or 0) <= 1:
        _add_unique_signal(negative, "Repeated low-value or single-indicator opportunity")
    if host in noisy_hosts and not positive:
        _add_unique_signal(negative, "CDN-only asset without validation signal")

    return {
        "validation_strength": _validation_strength(score),
        "validation_score": min(10, score),
        "positive_validation_signals": positive[:8],
        "negative_validation_signals": negative[:6],
    }


def _confidence_score_cap(confidence: str) -> int:
    return {"Low": 45, "Medium": 70, "High": 88, "Very High": 100}.get(confidence, 45)


def _evidence_summary(opportunity: HostOpportunity, strongest: List[OpportunityEvidence]) -> List[str]:
    summary = []
    if "GraphQL" in opportunity.opportunity_types:
        summary.append("GraphQL endpoint evidence")
    if "API" in opportunity.opportunity_types:
        summary.append("API/OpenAPI exposure evidence")
    if "Admin" in opportunity.opportunity_types:
        summary.append("Administrative surface evidence")
    if "Authentication" in opportunity.opportunity_types:
        summary.append("Authentication surface nearby")
    if "Debug" in opportunity.opportunity_types:
        summary.append("Debug or diagnostics surface nearby")
    if "Historical" in opportunity.opportunity_types:
        summary.append("Historical endpoint correlation")
    if "Parameters" in opportunity.opportunity_types:
        summary.append("Sensitive parameter names observed")
    for item in strongest:
        if item.reason not in summary:
            summary.append(item.reason)
    return summary[:6]


def _priority_reason(opportunity: HostOpportunity, strongest: List[OpportunityEvidence]) -> str:
    type_list = sorted(opportunity.opportunity_types)
    if "Historical" in opportunity.opportunity_types and _historical_only_opportunity(opportunity):
        return "Historical-only endpoint evidence requires live verification before active testing."
    if _correlation_strength(opportunity) >= 3:
        return "Multiple independent observations support manual investigation."
    if {"GraphQL", "Admin"}.issubset(opportunity.opportunity_types):
        return "GraphQL and administrative surface co-exist on the same host, creating a high-value authorization testing target."
    if {"API", "Parameters"}.issubset(opportunity.opportunity_types):
        return "API exposure combines with risky parameters, increasing the likelihood of IDOR, redirect, traversal, or authorization findings."
    if "Historical" in opportunity.opportunity_types:
        return "Historical endpoint is on a currently alive host and needs endpoint-level verification."
    if strongest:
        return strongest[0].reason
    return f"Combined opportunity signals: {', '.join(type_list)}"


def build_opportunity_priorities(scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    opportunities: Dict[str, HostOpportunity] = {}
    noisy_hosts = set()
    host_versions: Dict[str, Set[str]] = {}
    for row in scan_data.get("probe_rows", []) or []:
        if not isinstance(row, dict):
            continue
        host = _host(str(row.get("final_url") or row.get("url") or ""))
        text = " ".join(str(row.get(key) or "") for key in ("cdn", "waf", "server", "title")).lower()
        if any(token in text for token in NOISY_INFRASTRUCTURE_TOKENS):
            noisy_hosts.add(host)
        if _value_contains(text, AUTH_TOKENS):
            _host_opportunity(opportunities, host).add("Authentication", host, 30, "Authentication surface observed in probe metadata", source="probe")
        if _value_contains(text, ADMIN_TOKENS):
            _host_opportunity(opportunities, host).add("Admin", host, 45, "Administrative surface observed in probe metadata", source="probe")
        if any(token in host for token in ("dev", "staging", "test", "qa", "preview", "beta")):
            _host_opportunity(opportunities, host).add("Admin", host, 20, "Non-production host indicator observed", source="hostname")

    for row in scan_data.get("endpoint_rows", []) or []:
        endpoint = str(row.get("endpoint") if isinstance(row, dict) else row)
        if not endpoint:
            continue
        opportunity = _host_opportunity(opportunities, endpoint)
        lower = endpoint.lower()
        host = _host(endpoint)
        host_versions.setdefault(host, set()).update(match.group(0) for match in re.finditer(r"/v\d+", lower))
        if "graphql" in lower:
            opportunity.add("GraphQL", endpoint, 65, "GraphQL endpoint discovered", source="endpoint")
            category = str(row.get("category") if isinstance(row, dict) else "").lower()
            if "graphql" in category:
                opportunity.add("GraphQL", endpoint, 18, "GraphQL response/category indicator from endpoint analysis", source="endpoint_category")
        elif any(token in lower for token in ("swagger", "openapi")):
            opportunity.add("API", endpoint, 55, "API documentation or schema endpoint discovered", source="endpoint")
            category = str(row.get("category") if isinstance(row, dict) else "").lower()
            if "swagger" in category or "openapi" in category:
                opportunity.add("API", endpoint, 18, "OpenAPI/Swagger document indicator from endpoint analysis", source="endpoint_category")
        elif re.search(r"(^|/)api($|/|[-_])|/v\d+/", urlparse(endpoint if "://" in endpoint else f"https://{endpoint}").path.lower()):
            opportunity.add("API", endpoint, 40, "API endpoint discovered", source="endpoint")
        if _value_contains(lower, AUTH_TOKENS):
            opportunity.add("Authentication", endpoint, 35, "Authentication endpoint discovered", source="endpoint")
        if _value_contains(lower, ADMIN_TOKENS):
            opportunity.add("Admin", endpoint, 50, "Administrative endpoint discovered", source="endpoint")
        if _value_contains(lower, DEBUG_TOKENS):
            opportunity.add("Debug", endpoint, 50, "Debug or diagnostics endpoint discovered", source="endpoint")

    for row in scan_data.get("historical_endpoints", []) or []:
        endpoint = str(row.get("endpoint") if isinstance(row, dict) else row)
        if not endpoint:
            continue
        lower = endpoint.lower()
        opportunity = _host_opportunity(opportunities, endpoint)
        if "graphql" in lower:
            opportunity.add("GraphQL", endpoint, 30, "Historical GraphQL endpoint observed", source="historical_endpoint")
            opportunity.add("Historical", endpoint, 25, "Historical GraphQL endpoint observed", source="historical_endpoint")
        elif any(token in lower for token in ("swagger", "openapi", "/api", "/v1", "/v2", "/v3")):
            opportunity.add("Historical", endpoint, 25, "Historical API endpoint observed", source="historical_endpoint")
        if _value_contains(lower, ADMIN_TOKENS):
            opportunity.add("Admin", endpoint, 25, "Historical admin path observed", source="historical_endpoint")
            opportunity.add("Historical", endpoint, 25, "Historical admin path observed", source="historical_endpoint")

    for row in scan_data.get("content_discovery_rows", []) or []:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or "")
        path = str(row.get("path") or urlparse(url).path)
        score = int(row.get("signal_score") or 0)
        opportunity = _host_opportunity(opportunities, url)
        if _value_contains(path, ADMIN_TOKENS):
            opportunity.add("Admin", url, 45 if score < 70 else 55, "Focused content discovery found administrative surface", source="content_discovery")
        if "graphql" in path.lower():
            opportunity.add("GraphQL", url, 60, "Focused content discovery found GraphQL surface", source="content_discovery")
        elif _value_contains(path, API_TOKENS):
            opportunity.add("API", url, 35 if score < 70 else 45, "Focused content discovery found API surface", source="content_discovery")
        if _value_contains(path, DEBUG_TOKENS):
            opportunity.add("Debug", url, 45 if score < 70 else 55, "Focused content discovery found diagnostics surface", source="content_discovery")
        status = int(row.get("status_code") or 0)
        if status in {200, 401, 403} and ("swagger" in path.lower() or "openapi" in path.lower()):
            opportunity.add("API", url, 24, "OpenAPI/Swagger path returned an actionable response", source="content_response")
        if status in {200, 401, 403} and "graphql" in path.lower():
            opportunity.add("GraphQL", url, 24, "GraphQL path returned an actionable response", source="content_response")

    historical_diff = scan_data.get("historical_diff", {}) if isinstance(scan_data.get("historical_diff"), dict) else {}
    alive_historical_values = {
        str(value).strip().lower()
        for value in historical_diff.get("historical_and_currently_alive", [])
        if isinstance(historical_diff.get("historical_and_currently_alive"), list)
    }
    removed_historical_values = {
        str(value).strip().lower()
        for value in historical_diff.get("removed_apis", [])
        if isinstance(historical_diff.get("removed_apis"), list)
    }
    for key, reason in (
        ("historical_and_currently_alive", "Historical endpoint is on a currently alive host"),
        ("removed_apis", "Historical endpoint has no current equivalent in endpoint artifacts"),
        ("legacy_paths", "Legacy or deprecated path observed in historical data"),
    ):
        for url in historical_diff.get(key, []) if isinstance(historical_diff.get(key), list) else []:
            value = str(url)
            if key != "historical_and_currently_alive" and value.strip().lower() in alive_historical_values:
                continue
            if key == "legacy_paths" and value.strip().lower() in removed_historical_values:
                continue
            score = 60 if key == "historical_and_currently_alive" and _value_contains(value, API_TOKENS) else 45
            source = "historical_alive" if key == "historical_and_currently_alive" else "historical_removed" if key == "removed_apis" else "historical_legacy"
            opportunity = _host_opportunity(opportunities, value)
            opportunity.add("Historical", value, score, reason, source=source)
            if _value_contains(value, API_TOKENS):
                opportunity.add("API", value, 18, "Historical API indicator observed", source=source)

    host_risky_params = _host_risky_parameters(scan_data)
    global_risky_params = _parameter_tokens(scan_data.get("parameters", []) or [])
    for opportunity in opportunities.values():
        risky_params = host_risky_params.get(opportunity.host, [])
        if not risky_params and len(opportunities) == 1:
            risky_params = global_risky_params
        if risky_params and opportunity.opportunity_types.intersection({"API", "GraphQL", "Authentication", "Historical"}):
            source = "parameters" if opportunity.host in host_risky_params else "parameters_single_host"
            opportunity.add("Parameters", ", ".join(risky_params[:8]), min(35, 12 + len(risky_params) * 4), "Risky parameter names observed on this host", source=source)

    for host, versions in host_versions.items():
        if len(versions) >= 2 and host in opportunities:
            opportunities[host].add("API", ", ".join(sorted(versions)), 22, "Multiple API versions observed on the same host", source="endpoint_versions")

    for opportunity in opportunities.values():
        if {"GraphQL", "Admin"}.issubset(opportunity.opportunity_types):
            opportunity.add("GraphQL", opportunity.host, 35, "Combination bonus: GraphQL plus administrative surface", source="correlation")
        if "API" in opportunity.opportunity_types and "Parameters" in opportunity.opportunity_types:
            opportunity.add("Parameters", opportunity.host, 25, "Combination bonus: API exposure plus risky parameters", source="correlation")
        if "Historical" in opportunity.opportunity_types and ("API" in opportunity.opportunity_types or "GraphQL" in opportunity.opportunity_types):
            opportunity.add("Historical", opportunity.host, 25, "Combination bonus: historical API surface", source="correlation")
        if opportunity.host in noisy_hosts and not opportunity.opportunity_types.intersection({"GraphQL", "Admin", "Debug", "Historical", "API"}):
            opportunity.noise_penalty = 30

    rows = []
    for item in opportunities.values():
        if not item.evidence:
            continue
        row = item.to_report_row()
        row.update(_opportunity_validation(item, row, scan_data, noisy_hosts))
        rows.append(row)
    rows.sort(key=lambda item: (-int(item["score"]), str(item["host"])))
    return rows[:20]


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
        if confidence.strip().lower() == "high":
            score += 20
            reason += "; strong CMS/framework mapping"
        else:
            score -= 20
            reason += "; CMS/framework mapping requires high-confidence evidence"
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
        scored.append(
            {
                "technology": "Cloud Assets",
                "tags": ["cloud", "exposure", "misconfig"],
                "score": 65,
                "accepted": False,
                "reason": "Cloud storage/service reference observed; kept informational to avoid broad scans",
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
    atomic_write_text(path, "\n".join(lines).strip() + ("\n" if lines else ""), encoding="utf-8")


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
    noise = _noise_assessment(scan_data, infrastructure, cloud_assets)
    priorities = build_investigation_priorities(scan_data, risk)
    opportunity_priorities = build_opportunity_priorities(scan_data)

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
    write_json(intel_dir / "noise_assessment.json", noise)
    write_json(intel_dir / "investigation_priorities.json", priorities)
    write_json(intel_dir / "opportunity_priorities.json", opportunity_priorities)
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
            "Investigation Priorities": len(priorities),
            "Top Opportunities": len(opportunity_priorities),
            "Noise": noise.get("assessment", "Not assessed"),
            "Template Tags": ", ".join(template_intel.get("selected_tags", [])) or "Not Run",
            "Output Location": intel_dir,
        },
    )
    log.info("Intelligence generated in %.2fs", duration)
    success("Intelligence layer generated")
    return ModuleResult()
