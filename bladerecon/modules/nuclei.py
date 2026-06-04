"""Nuclei wrapper module.

Provides a `run` function that checks for the `nuclei` binary, runs it with
specified templates/severity, captures JSON output and renders a simple
Markdown summary. Results are saved under `output/<target>/nuclei/`.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from rich.console import Console
from rich.markup import escape
console = Console()

from .intelligence import TEMPLATE_TAGS
from .utils import ModuleResult, atomic_write_text, config_get, deduplicate_alive_urls, format_duration, get_profiled_ceiling, get_profiled_concurrency, get_profiled_rate_limit, get_timeout, info, load_config, log_duration, normalize_scan_profile, normalize_target, nuclei_template_status, prepare_module_output, print_module_summary, setup_logging, skipped_result, skip, success, suppress_third_party_banner, target_output_dir, warn, write_json

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")


def _nuclei_exists() -> bool:
    """Return True if `nuclei` binary is in PATH."""
    return shutil.which("nuclei") is not None


def _suggest_install() -> str:
    """Return a suggested nuclei installation command string."""
    if platform.system() == "Windows":
        return "bladerecon install-deps"
    return "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"


def _severity_counts(findings: List[dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        severity = str(finding.get("info", {}).get("severity") or finding.get("severity") or "unknown").lower()
        counts[severity if severity in counts else "unknown"] += 1
    return counts


def _parse_jsonl(json_text: str) -> Tuple[List[dict], int]:
    findings: List[dict] = []
    malformed = 0
    for line in json_text.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                findings.append(obj)
            else:
                malformed += 1
        except json.JSONDecodeError:
            malformed += 1
    return findings, malformed


def _write_results(output_dir: Path, json_text: str) -> None:
    """Write raw JSON output and a simple Markdown summary."""
    output_dir.mkdir(parents=True, exist_ok=True)
    json_file = output_dir / "results.json"
    jsonl_file = output_dir / "results.jsonl"
    md_file = output_dir / "results.md"

    findings, malformed = _parse_jsonl(json_text)

    write_json(json_file, findings)
    atomic_write_text(jsonl_file, json_text, encoding="utf-8")

    counts = _severity_counts(findings)
    md_lines: List[str] = [
        "# Nuclei Results",
        "",
        f"Total findings: {len(findings)}",
        "",
        "## Severity Summary",
        "",
    ]
    for severity in SEVERITY_ORDER:
        md_lines.append(f"- **{severity.title()}**: {counts.get(severity, 0)}")
    if malformed:
        md_lines.append(f"- **Malformed JSONL lines skipped**: {malformed}")
    md_lines.append("")

    grouped: Dict[str, List[dict]] = {severity: [] for severity in SEVERITY_ORDER}
    for finding in findings:
        severity = str(finding.get("info", {}).get("severity") or finding.get("severity") or "unknown").lower()
        grouped.setdefault(severity if severity in grouped else "unknown", []).append(finding)

    for severity in SEVERITY_ORDER:
        items = grouped.get(severity, [])
        if not items:
            continue
        md_lines.append(f"## {severity.title()} ({len(items)})")
        md_lines.append("")
        for f in sorted(items, key=lambda item: str(item.get("host") or item.get("matched") or "")):
            name = f.get("info", {}).get("name") or f.get("template") or "Unnamed"
            host = f.get("host") or f.get("matched") or "<unknown>"
            path = f.get("matched-at") or f.get("matched-at-path") or f.get("path") or ""
            description = f.get("info", {}).get("description") or ""

            md_lines.append(f"### {escape(str(name))}")
            md_lines.append(f"- **Host:** {escape(str(host))}")
            if path:
                md_lines.append(f"- **Path:** {escape(str(path))}")
            if description:
                md_lines.append(f"- **Description:** {escape(str(description))}")
            md_lines.append("")

    atomic_write_text(md_file, "\n".join(md_lines), encoding="utf-8")
    console.print(f"[green]Wrote nuclei results:[/] {json_file}, {jsonl_file}, and {md_file}")


def _dedupe_jsonl_text(json_text: str) -> str:
    """Deduplicate Nuclei JSONL findings while preserving first-seen order."""
    findings, _ = _parse_jsonl(json_text)
    seen: Set[Tuple[str, str, str]] = set()
    lines: List[str] = []
    for finding in findings:
        key = (
            str(finding.get("template") or ""),
            str(finding.get("host") or finding.get("matched") or ""),
            str(finding.get("matched-at") or finding.get("matched-at-path") or finding.get("path") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        lines.append(json.dumps(finding, sort_keys=True))
    return "\n".join(lines) + ("\n" if lines else "")


def _load_detected_technologies(output: Path, target_name: str) -> List[str]:
    path = target_output_dir(output, target_name) / "technologies" / "technologies.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return []
    detected = set()
    if isinstance(data, list):
        for row in data:
            if not isinstance(row, dict):
                continue
            for item in row.get("detected", []) or []:
                value = str(item).strip()
                if value:
                    detected.add(value)
    return sorted(detected)


def _load_template_intelligence(output: Path, target_name: str) -> Dict[str, object]:
    path = target_output_dir(output, target_name) / "intelligence" / "template_intelligence.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _read_json_file(path: Path, default: object) -> object:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return default


def _nuclei_roi_decision(output: Path, target_name: str, baseline_only: bool, selected_tags: List[str], explicit_templates: bool, automatic_scan: bool) -> Dict[str, object]:
    """Decide whether a baseline-only Nuclei run has enough opportunity evidence."""
    def to_int(value: object) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    if explicit_templates:
        return {"run": True, "reason": "explicit templates supplied"}
    if selected_tags:
        return {"run": True, "reason": "high-confidence intelligence tags selected"}
    if automatic_scan:
        return {"run": True, "reason": "automatic scan enabled"}
    if not baseline_only:
        return {"run": True, "reason": "non-baseline execution"}

    target_dir = target_output_dir(output, target_name)
    opportunities = _read_json_file(target_dir / "intelligence" / "opportunity_priorities.json", [])
    high_confidence = []
    validated = []
    if isinstance(opportunities, list):
        for item in opportunities:
            if not isinstance(item, dict):
                continue
            confidence = str(item.get("confidence") or "").lower()
            score = to_int(item.get("score"))
            validation_strength = str(item.get("validation_strength") or "").lower()
            positive = item.get("positive_validation_signals")
            if confidence == "high" and score >= 70:
                high_confidence.append(item)
            strong_positive = False
            if isinstance(positive, list):
                positive_text = " ".join(str(value).lower() for value in positive)
                strong_positive = any(
                    token in positive_text
                    for token in (
                        "nuclei finding",
                        "endpoint artifacts",
                        "returned actionable response",
                        "access confirmed",
                        "interesting response pattern",
                    )
                )
            if validation_strength in {"moderate", "strong"} or strong_positive:
                validated.append(item)

    asset_priority = _read_json_file(target_dir / "asset_priority.json", {})
    top_assets = asset_priority.get("top_assets", []) if isinstance(asset_priority, dict) else []
    strong_assets = [
        item for item in top_assets
        if isinstance(item, dict) and to_int(item.get("score")) >= 70 and str(item.get("confidence") or "").lower() == "high"
    ]

    if high_confidence or validated or strong_assets:
        return {
            "run": True,
            "reason": "baseline justified by high-confidence or validated opportunity evidence",
            "high_confidence_opportunities": len(high_confidence),
            "validated_opportunities": len(validated),
            "strong_assets": len(strong_assets),
        }
    return {
        "run": False,
        "reason": "baseline-only scan skipped: no selected intelligence tags, no high-confidence opportunities, and no validated attack surface",
        "high_confidence_opportunities": 0,
        "validated_opportunities": 0,
        "strong_assets": 0,
    }


def _write_nuclei_skip_artifacts(out_dir: Path, metadata: Dict[str, object]) -> None:
    write_json(out_dir / "results.json", [])
    atomic_write_text(out_dir / "results.jsonl", "", encoding="utf-8")
    atomic_write_text(
        out_dir / "results.md",
        "\n".join(["# Nuclei Results", "", "Total findings: 0", "", f"Skipped: {metadata.get('skip_reason', metadata.get('reason', 'not run'))}", ""]),
        encoding="utf-8",
    )
    write_json(out_dir / "metadata.json", metadata)


def _load_template_target_hosts(output: Path, target_name: str, selected_tags: List[str]) -> Tuple[List[str], List[str]]:
    if not selected_tags:
        return [], []
    selected = {tag.strip().lower() for tag in selected_tags if tag.strip()}
    path = target_output_dir(output, target_name) / "technology" / "technology.json"
    if not path.exists():
        return [], sorted(selected)
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return [], sorted(selected)
    if not isinstance(data, list):
        return [], sorted(selected)

    hosts: Set[str] = set()
    mapped_tags: Set[str] = set()
    for row in data:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "")
        row_tags = {tag.lower() for tag in TEMPLATE_TAGS.get(name, [])}
        if not row_tags.intersection(selected):
            continue
        mapped_tags.update(row_tags.intersection(selected))
        for host in row.get("hosts", []) if isinstance(row.get("hosts"), list) else []:
            value = str(host).strip().lower()
            if value:
                hosts.add(value)
    return sorted(hosts), sorted(selected - mapped_tags)


def _scope_target_list(
    target_list: Optional[Path],
    output: Path,
    target_name: str,
    out_dir: Path,
    selected_tags: List[str],
    explicit_list: bool,
) -> Dict[str, object]:
    if explicit_list or not target_list or not target_list.exists() or not selected_tags:
        return {"enabled": False, "reason": ""}
    target_hosts, unmatched_tags = _load_template_target_hosts(output, target_name, selected_tags)
    if unmatched_tags or not target_hosts:
        return {"enabled": False, "reason": "selected tags were not fully mapped to target hosts"}
    target_host_set = set(target_hosts)
    raw_targets = [line.strip() for line in target_list.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    scoped_targets: List[str] = []
    for target in raw_targets:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = (parsed.hostname or target).lower()
        if host in target_host_set:
            scoped_targets.append(target)
    if not scoped_targets or len(scoped_targets) >= len(raw_targets):
        return {"enabled": False, "reason": "scope did not reduce target set"}
    scoped_file = out_dir / "scoped_targets.txt"
    scoped_file.write_text("\n".join(scoped_targets) + "\n", encoding="utf-8")
    return {
        "enabled": True,
        "path": str(scoped_file),
        "original_targets": len(raw_targets),
        "scoped_targets": len(scoped_targets),
        "host_scope": target_hosts,
        "reason": "technology-tag target scope",
    }


def _opportunity_host(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else f"https://{text}")
    return (parsed.hostname or text.split("/")[0]).lower()


def _load_roi_target_hosts(output: Path, target_name: str, max_hosts: int = 10) -> List[str]:
    """Return hosts with enough opportunity evidence to justify baseline-only Nuclei."""
    path = target_output_dir(output, target_name) / "intelligence" / "opportunity_priorities.json"
    opportunities = _read_json_file(path, [])
    if not isinstance(opportunities, list):
        return []

    def to_int(value: object) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    strength_rank = {"strong": 3, "moderate": 2, "weak": 1, "none": 0, "": 0}
    ranked: List[Tuple[int, int, str]] = []
    seen: Set[str] = set()
    for item in opportunities:
        if not isinstance(item, dict):
            continue
        host = _opportunity_host(item.get("target"))
        if not host or host in seen:
            continue
        score = to_int(item.get("score"))
        confidence = str(item.get("confidence") or "").lower()
        strength = str(item.get("validation_strength") or "").lower()
        opportunity_type = str(item.get("opportunity_type") or "").lower()
        historical_only = opportunity_type == "historical" and strength not in {"moderate", "strong"}
        if historical_only:
            continue
        if strength in {"moderate", "strong"} or (confidence == "high" and score >= 70):
            ranked.append((score, strength_rank.get(strength, 0), host))
            seen.add(host)

    ranked.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    asset_priority = _read_json_file(target_output_dir(output, target_name) / "asset_priority.json", {})
    top_assets = asset_priority.get("top_assets", []) if isinstance(asset_priority, dict) else []
    for item in top_assets if isinstance(top_assets, list) else []:
        if not isinstance(item, dict):
            continue
        host = _opportunity_host(item.get("host") or item.get("url") or item.get("target"))
        if not host or host in seen:
            continue
        score = to_int(item.get("score"))
        confidence = str(item.get("confidence") or "").lower()
        if score >= 70 and confidence == "high":
            ranked.append((score, 1, host))
            seen.add(host)

    ranked.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    return [host for _, _, host in ranked[:max_hosts]]


def _scope_baseline_targets_to_roi(
    target_domain: Optional[str],
    target_list: Optional[Path],
    output: Path,
    target_name: str,
    out_dir: Path,
    max_hosts: int,
) -> Tuple[Optional[str], Optional[Path], Dict[str, object]]:
    roi_hosts = _load_roi_target_hosts(output, target_name, max_hosts=max_hosts)
    if not roi_hosts:
        return target_domain, target_list, {"enabled": False, "reason": "no ROI opportunity hosts"}
    roi_host_set = set(roi_hosts)

    if target_list and target_list.exists():
        raw_targets = [line.strip() for line in target_list.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
        scoped_targets: List[str] = []
        for target in raw_targets:
            parsed = urlparse(target if "://" in target else f"https://{target}")
            host = (parsed.hostname or target).lower()
            if host in roi_host_set:
                scoped_targets.append(target)
        if not scoped_targets:
            return None, target_list, {
                "enabled": False,
                "reason": "ROI opportunity hosts were not present in current target list",
                "host_scope": roi_hosts,
                "original_targets": len(raw_targets),
                "scoped_targets": 0,
            }
        if len(scoped_targets) >= len(raw_targets):
            return target_domain, target_list, {
                "enabled": False,
                "reason": "ROI scope did not reduce target set",
                "host_scope": roi_hosts,
                "original_targets": len(raw_targets),
                "scoped_targets": len(scoped_targets),
            }
        scoped_file = out_dir / "opportunity_targets.txt"
        scoped_file.write_text("\n".join(scoped_targets) + "\n", encoding="utf-8")
        return None, scoped_file, {
            "enabled": True,
            "path": str(scoped_file),
            "original_targets": len(raw_targets),
            "scoped_targets": len(scoped_targets),
            "host_scope": roi_hosts,
            "reason": "opportunity ROI target scope",
        }

    if target_domain:
        host = _opportunity_host(target_domain)
        if host in roi_host_set:
            return target_domain, None, {
                "enabled": False,
                "reason": "single target already matches ROI opportunity host",
                "host_scope": roi_hosts,
                "original_targets": 1,
                "scoped_targets": 1,
            }
        return None, None, {
            "enabled": False,
            "reason": "single target did not match ROI opportunity hosts",
            "host_scope": roi_hosts,
            "original_targets": 1,
            "scoped_targets": 0,
        }
    return target_domain, target_list, {"enabled": False, "reason": "no current nuclei targets", "host_scope": roi_hosts}


def _count_matching_templates(base_cmd: List[str], timeout: int = 60) -> Optional[int]:
    """Return nuclei's matching template count for the same filters, when cheap."""
    cmd: List[str] = ["nuclei"]
    skip_next = False
    target_flags = {"-u", "-target", "-l", "-list", "-j", "-jsonl", "-nc", "-as", "-automatic-scan"}
    for index, item in enumerate(base_cmd[1:], start=1):
        if skip_next:
            skip_next = False
            continue
        if item in {"-u", "-target", "-l", "-list"}:
            skip_next = True
            continue
        if item in target_flags:
            continue
        cmd.append(item)
    cmd += ["-tl", "-silent", "-duc"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    return len([line for line in proc.stdout.splitlines() if line.strip()])


def _parse_loaded_template_count(stderr: str) -> Optional[int]:
    patterns = (
        r"templates loaded for current scan:\s*(\d+)",
        r"templates loaded:\s*(\d+)",
    )
    for pattern in patterns:
        match = re.search(pattern, stderr, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _count_targets(target_domain: Optional[str], target_list: Optional[Path]) -> int:
    if target_list and target_list.exists():
        return len([line for line in target_list.read_text(encoding="utf-8-sig").splitlines() if line.strip()])
    return 1 if target_domain else 0


def _normalize_target_list_file(target_list: Path, out_dir: Path) -> Path:
    """Write a BOM-free target list for Nuclei and return its path."""
    raw = target_list.read_text(encoding="utf-8-sig")
    targets = [line.strip() for line in raw.splitlines() if line.strip()]
    normalized = out_dir / "targets_normalized.txt"
    normalized.write_text("\n".join(targets) + ("\n" if targets else ""), encoding="utf-8")
    return normalized


def _resolve_target_file(domain: Optional[str], list_file: Optional[Path], output: Path) -> Tuple[Optional[str], Optional[Path], str]:
    """Prefer alive hosts for domain scans and return target metadata."""
    if list_file:
        return None, list_file, normalize_target(list_file.stem)
    if not domain:
        return None, None, "nuclei"
    safe_domain = normalize_target(domain)
    alive_file = target_output_dir(output, safe_domain) / "probe" / "alive.txt"
    if alive_file.exists():
        alive_text = alive_file.read_text(encoding="utf-8-sig")
        if not alive_text.strip():
            return None, alive_file, safe_domain
        urls = deduplicate_alive_urls(alive_text.splitlines())
        alive_file.write_text("\n".join(urls), encoding="utf-8")
        return None, alive_file, safe_domain
    return domain, None, safe_domain


def _profile_settings(profile: str) -> dict:
    config = load_config()
    profile = normalize_scan_profile(profile, config)
    profiles = config_get(config, "nuclei_profiles", {})
    selected = profiles.get(profile)
    if not isinstance(selected, dict):
        warn(f"Unknown nuclei profile '{profile}', falling back to balanced")
        selected = profiles.get("balanced", {})
    return selected


def _missing_templates(stderr: str) -> bool:
    value = stderr.lower()
    return "no templates provided" in value or "no templates found" in value or "nuclei-templates are not installed" in value


def _no_templates_for_filters(stderr: str) -> bool:
    value = stderr.lower()
    return (
        "could not find any templates with tech tag" in value
        or "no templates found for" in value
        or "no templates found with" in value
        or "no templates provided for scan" in value
    )


def _remove_flag_with_value(cmd: List[str], flag: str) -> List[str]:
    cleaned: List[str] = []
    skip_next = False
    for item in cmd:
        if skip_next:
            skip_next = False
            continue
        if item == flag:
            skip_next = True
            continue
        cleaned.append(item)
    return cleaned


def _replace_flag_value(cmd: List[str], flag: str, value: str) -> List[str]:
    cleaned = _remove_flag_with_value(cmd, flag)
    cleaned += [flag, value]
    return cleaned


def _baseline_target_command(base_cmd: List[str], target_domain: Optional[str], target_list: Optional[Path]) -> List[str]:
    cmd = _remove_flag_with_value(base_cmd, "-tags")
    cmd = _remove_flag_with_value(cmd, "-u")
    cmd = _remove_flag_with_value(cmd, "-l")
    if target_list:
        cmd += ["-l", str(target_list)]
    elif target_domain:
        cmd += ["-u", str(target_domain)]
    return cmd


def _baseline_practicality(
    enabled: bool,
    selected_tags: List[str],
    explicit_templates: bool,
    baseline_target_count: int,
    max_targets: int,
) -> Tuple[bool, str]:
    if not enabled:
        return False, "disabled by configuration"
    if explicit_templates:
        return False, "explicit templates supplied"
    if not selected_tags:
        return False, "no intelligence tags selected"
    if max_targets > 0 and baseline_target_count > max_targets:
        return False, f"target count {baseline_target_count} exceeds baseline safety ceiling {max_targets}"
    return True, "smart-tag coverage safety net"


def _target_hosts_from_domain_or_list(target_domain: Optional[str], target_list: Optional[Path]) -> Set[str]:
    hosts: Set[str] = set()
    if target_list and target_list.exists():
        for line in target_list.read_text(encoding="utf-8-sig").splitlines():
            value = line.strip()
            if not value:
                continue
            host = _opportunity_host(value)
            if host:
                hosts.add(host)
    elif target_domain:
        host = _opportunity_host(target_domain)
        if host:
            hosts.add(host)
    return hosts


def _scope_smart_baseline_targets(
    original_target_domain: Optional[str],
    original_target_list: Optional[Path],
    current_target_domain: Optional[str],
    current_target_list: Optional[Path],
    output: Path,
    target_name: str,
    out_dir: Path,
    max_hosts: int,
) -> Tuple[Optional[str], Optional[Path], Dict[str, object]]:
    roi_hosts = _load_roi_target_hosts(output, target_name, max_hosts=max_hosts)
    current_hosts = _target_hosts_from_domain_or_list(current_target_domain, current_target_list)
    original_lines: Dict[str, str] = {}
    if original_target_list and original_target_list.exists():
        for line in original_target_list.read_text(encoding="utf-8-sig").splitlines():
            value = line.strip()
            host = _opportunity_host(value)
            if value and host:
                original_lines.setdefault(host, value)
    elif original_target_domain:
        host = _opportunity_host(original_target_domain)
        if host:
            original_lines[host] = original_target_domain

    gap_hosts = [host for host in roi_hosts if host not in current_hosts]
    scoped_targets = [original_lines[host] for host in gap_hosts if host in original_lines]
    if not roi_hosts:
        return None, None, {
            "run": False,
            "reason": "no high-confidence or validated opportunity gap for baseline",
            "roi_hosts": [],
            "covered_hosts": sorted(current_hosts),
            "gap_hosts": [],
            "targets": [],
        }
    if not gap_hosts:
        return None, None, {
            "run": False,
            "reason": "scoped smart scan already covers high-confidence opportunity hosts",
            "roi_hosts": roi_hosts,
            "covered_hosts": sorted(current_hosts),
            "gap_hosts": [],
            "targets": [],
        }
    if not scoped_targets:
        return None, None, {
            "run": False,
            "reason": "baseline opportunity hosts were not present in the active target list",
            "roi_hosts": roi_hosts,
            "covered_hosts": sorted(current_hosts),
            "gap_hosts": gap_hosts,
            "targets": [],
        }
    scoped_file = out_dir / "baseline_opportunity_targets.txt"
    scoped_file.write_text("\n".join(scoped_targets) + "\n", encoding="utf-8")
    return None, scoped_file, {
        "run": True,
        "reason": "baseline scoped to uncovered high-confidence opportunity hosts",
        "roi_hosts": roi_hosts,
        "covered_hosts": sorted(current_hosts),
        "gap_hosts": gap_hosts,
        "targets": scoped_targets,
        "path": str(scoped_file),
    }


def _default_template_dir() -> Path:
    home = Path(os.path.expanduser("~"))
    return home / "nuclei-templates"


def _has_templates(template_dir: Path) -> bool:
    if not template_dir.exists() or not template_dir.is_dir():
        return False
    return any(template_dir.rglob("*.yaml")) or any(template_dir.rglob("*.yml"))


def _update_templates(timeout: int, template_dir: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    cmd = ["nuclei", "-update-templates"]
    if template_dir:
        cmd += ["-update-template-dir", str(template_dir)]
    return subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout)


def _clean_nuclei_output(text: str) -> str:
    return suppress_third_party_banner(text, tool="nuclei")


def _run_nuclei_process(cmd: List[str], timeout: int, out_dir: Path, template_total: Optional[int], target_count: int, enforce_timeout: bool = False, progress_interval: int = 10) -> subprocess.CompletedProcess[str]:
    stdout_path = out_dir / "stdout.tmp"
    stderr_path = out_dir / "stderr.tmp"
    timeout_detail = f" timeout={format_duration(timeout)}" if enforce_timeout and timeout > 0 else " timeout=monitor-only"
    template_detail = f" templates={template_total}" if template_total is not None else " templates=unknown"
    info(f"Nuclei execution started: targets={target_count}{template_detail}{timeout_detail}")
    started = time.perf_counter()
    last_status = started
    proc: Optional[subprocess.Popen[str]] = None
    try:
        with stdout_path.open("w", encoding="utf-8") as stdout_fh, stderr_path.open("w", encoding="utf-8") as stderr_fh:
            proc = subprocess.Popen(cmd, stdout=stdout_fh, stderr=stderr_fh, text=True)
            while proc.poll() is None:
                elapsed = time.perf_counter() - started
                if enforce_timeout and timeout > 0 and elapsed >= timeout:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                    raise subprocess.TimeoutExpired(cmd, timeout)
                if elapsed >= progress_interval and time.perf_counter() - last_status >= progress_interval:
                    info(f"Nuclei still running: elapsed={format_duration(elapsed)} targets={target_count}{template_detail}")
                    last_status = time.perf_counter()
                time.sleep(1)
        stdout = stdout_path.read_text(encoding="utf-8-sig") if stdout_path.exists() else ""
        stderr = stderr_path.read_text(encoding="utf-8-sig") if stderr_path.exists() else ""
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        stdout_path.unlink(missing_ok=True)
        stderr_path.unlink(missing_ok=True)
    info(f"Nuclei execution completed: elapsed={format_duration(time.perf_counter() - started)} targets={target_count}{template_detail}")
    return subprocess.CompletedProcess(cmd, int(proc.returncode or 0), stdout, stderr)


def run(
    domain: Optional[str] = None,
    list_file: Optional[Path] = None,
    profile: str = "balanced",
    severity: Optional[str] = None,
    exclude_tags: Optional[str] = None,
    templates: Optional[Path] = None,
    update_templates: bool = False,
    concurrency: Optional[int] = None,
    timeout: Optional[int] = None,
    output: Path = Path("results"),
    resume: bool = False,
) -> ModuleResult:
    """Run nuclei against a domain or a list of targets.

    - `domain`: single target (will be passed with `-u` to nuclei)
    - `list_file`: path to newline-separated targets (passed with `-l`)
    - `profile`: safe, balanced, or full
    - `severity`: optional comma-separated severity override
    - `templates`: optional path to nuclei templates
    - `output`: base results folder
    """
    if not domain and not list_file:
        warn("Either --domain or --list is required")
        return ModuleResult()

    config = load_config()
    profile = normalize_scan_profile(profile, config)
    target_domain, target_list, target_name = _resolve_target_file(domain, list_file, output)
    original_target_domain = target_domain
    original_target_list = target_list
    log = setup_logging(target_name, output, "nuclei")
    started = time.perf_counter()
    out_dir = prepare_module_output(output, target_name, "nuclei", resume=resume)

    if not _nuclei_exists():
        log.warning("nuclei binary not found")
        result = skipped_result("Binary not installed")
        skip("Nuclei module skipped")
        info("Reason: nuclei binary not found in PATH")
        print_module_summary(
            "Nuclei Summary",
            {
                "Target": target_name,
                "Duration": f"{time.perf_counter() - started:.2f}s",
                "Nuclei Status": "Skipped",
                "Reason": result.reason,
            },
        )
        return result

    cmd: List[str] = ["nuclei"]
    if target_list:
        if not target_list.exists() or not target_list.read_text(encoding="utf-8-sig").strip():
            skip("Nuclei module skipped")
            info("Reason: no alive targets")
            log.warning("No nuclei targets found")
            return skipped_result("No alive targets")
        normalized_target_list = _normalize_target_list_file(target_list, out_dir)
        if original_target_list == target_list:
            original_target_list = normalized_target_list
        target_list = normalized_target_list
        cmd += ["-l", str(target_list)]
    else:
        cmd += ["-u", str(target_domain)]

    explicit_templates = templates is not None
    if templates:
        cmd += ["-t", str(templates)]

    settings = _profile_settings(profile)
    resolved_severity = severity or str(settings.get("severity") or "critical,high,medium,low")
    resolved_exclude_tags = exclude_tags if exclude_tags is not None else str(settings.get("exclude_tags") or "")
    resolved_rate = int(settings.get("rate_limit") or get_profiled_rate_limit("nuclei", 25, profile, config))
    resolved_concurrency = concurrency or get_profiled_concurrency("nuclei", 25, profile, config)
    baseline_enabled = bool(config_get(config, "nuclei.baseline_scan.enabled", True))
    baseline_severity = str(config_get(config, "nuclei.baseline_scan.severity", "critical,high") or "critical,high")
    baseline_tags = str(config_get(config, "nuclei.baseline_scan.tags", "cve,exposure,misconfig") or "").strip()
    baseline_max_targets = int(config_get(config, "nuclei.baseline_scan.max_targets", 50) or 0)
    detected_technologies = _load_detected_technologies(output, target_name)
    template_intelligence = _load_template_intelligence(output, target_name)
    selected_tags_requested = [
        str(tag).strip()
        for tag in template_intelligence.get("selected_tags", [])  # type: ignore[union-attr]
        if str(tag).strip()
    ] if isinstance(template_intelligence.get("selected_tags"), list) else []
    selected_tags = list(selected_tags_requested)
    automatic_scan = bool(config_get(config, "nuclei.automatic_scan", False)) and not explicit_templates and not selected_tags
    baseline_only = baseline_enabled and not explicit_templates and not selected_tags and not automatic_scan
    if baseline_only:
        resolved_severity = baseline_severity
    selection_reason = "explicit templates" if explicit_templates else "intelligence tags" if selected_tags else "automatic scan" if automatic_scan else "baseline-only: no high-confidence intelligence tags" if baseline_only else f"profile {profile}"
    target_scope = _scope_target_list(target_list, output, target_name, out_dir, selected_tags, explicit_list=list_file is not None)
    if target_scope.get("enabled"):
        cmd = _remove_flag_with_value(cmd, "-l")
        cmd = _remove_flag_with_value(cmd, "-u")
        target_list = Path(str(target_scope["path"]))
        target_domain = None
        cmd += ["-l", str(target_list)]
        selection_reason += "; scoped to matching technology hosts"

    if resolved_severity:
        cmd += ["-severity", resolved_severity]
    if resolved_exclude_tags:
        cmd += ["-exclude-tags", resolved_exclude_tags]
    if resolved_rate:
        cmd += ["-rl", str(resolved_rate)]
    if resolved_concurrency:
        cmd += ["-c", str(resolved_concurrency)]
    if selected_tags and not explicit_templates:
        cmd += ["-tags", ",".join(selected_tags)]
    elif baseline_only and baseline_tags:
        cmd += ["-tags", baseline_tags]
    if automatic_scan:
        cmd += ["-as"]

    module_timeout = int(timeout if timeout is not None else config_get(config, "nuclei.module_timeout", get_timeout("nuclei", 300)) or 0)
    enforce_module_timeout = bool(config_get(config, "nuclei.enforce_module_timeout", False))
    progress_interval = int(config_get(config, "nuclei.progress_interval", 10) or 10)
    cmd += ["-timeout", str(config_get(config, "nuclei.request_timeout", 8)), "-retries", str(config_get(config, "nuclei.retries", 0)), "-j", "-nc", "-duc"]

    default_template_dir = _default_template_dir()
    if update_templates:
        info("Updating nuclei templates")
        subprocess.run(
            ["nuclei", "-update-templates", "-update-template-dir", str(default_template_dir)],
            capture_output=True,
            text=True,
            check=False,
            timeout=module_timeout or get_timeout("nuclei", 300),
        )
        if not explicit_templates and _has_templates(default_template_dir):
            cmd += ["-t", str(default_template_dir)]

    template_status = nuclei_template_status(templates or default_template_dir, require_checksum=not explicit_templates)
    if not template_status["ok"]:
        reason = f"templates unavailable at {template_status['path']}. Run: nuclei -ut"
        warn("Nuclei templates are not installed.")
        info("Run: nuclei -ut")
        print_module_summary(
            "Nuclei Summary",
            {
                "Target": target_name,
                "Duration": f"{time.perf_counter() - started:.2f}s",
                "Nuclei Status": "Skipped",
                "Reason": reason,
            },
        )
        log.warning("Nuclei skipped: %s", reason)
        return skipped_result(reason)

    target_count = _count_targets(target_domain, target_list)
    target_ceiling = get_profiled_ceiling("nuclei_targets", 250, profile, config)
    if target_list and target_ceiling and target_count > target_ceiling:
        raw_targets = [line.strip() for line in target_list.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
        capped_file = out_dir / "targets_capped.txt"
        capped_file.write_text("\n".join(raw_targets[:target_ceiling]) + "\n", encoding="utf-8")
        warn(f"Nuclei targets capped at {target_ceiling} of {target_count} by active safety profile")
        cmd = _remove_flag_with_value(cmd, "-l")
        cmd += ["-l", str(capped_file)]
        target_list = capped_file
        target_count = target_ceiling
    if baseline_only and target_list and baseline_max_targets > 0 and target_count > baseline_max_targets:
        raw_targets = [line.strip() for line in target_list.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
        capped_file = out_dir / "baseline_only_targets_capped.txt"
        capped_file.write_text("\n".join(raw_targets[:baseline_max_targets]) + "\n", encoding="utf-8")
        warn(f"Nuclei baseline-only targets capped at {baseline_max_targets} of {target_count}")
        cmd = _remove_flag_with_value(cmd, "-l")
        cmd += ["-l", str(capped_file)]
        target_list = capped_file
        target_count = baseline_max_targets
    roi_gate_enabled = bool(config_get(config, "nuclei.roi_gate.enabled", True))
    roi_decision = _nuclei_roi_decision(
        output,
        target_name,
        baseline_only=baseline_only,
        selected_tags=selected_tags,
        explicit_templates=explicit_templates,
        automatic_scan=automatic_scan,
    )
    if roi_gate_enabled and not bool(roi_decision.get("run", True)):
        duration = time.perf_counter() - started
        reason = str(roi_decision.get("reason") or "baseline-only scan skipped: insufficient opportunity evidence")
        metadata = {
            "profile": profile,
            "status": "skipped",
            "skip_reason": reason,
            "severity": resolved_severity,
            "exclude_tags": resolved_exclude_tags,
            "automatic_scan": automatic_scan,
            "baseline_only": baseline_only,
            "detected_technologies": detected_technologies,
            "template_intelligence": template_intelligence,
            "selected_tags_requested": selected_tags_requested,
            "selected_tags": selected_tags,
            "selection_reason": selection_reason,
            "coverage_strategy": "skipped_low_roi_baseline",
            "roi_decision": roi_decision,
            "baseline_reason": reason,
            "baseline_skip_reason": reason,
            "baseline_roi": {"run": False, "reason": reason, "targets": []},
            "baseline_targets": [],
            "target_scope": target_scope,
            "template_candidates": None,
            "template_count_preflight": False,
            "templates_executed": 0,
            "templates_skipped": None,
            "baseline_scan": {
                "enabled": baseline_enabled,
                "applied": False,
                "status": "skipped",
                "reason": reason,
                "skip_reason": reason,
                "roi": {"run": False, "reason": reason, "targets": []},
                "targets": [],
                "severity": baseline_severity,
                "tags": baseline_tags,
                "max_targets": baseline_max_targets,
                "template_candidates": None,
                "templates_executed": 0,
                "targets_count": 0,
                "duration_seconds": 0.0,
            },
            "targets_count": target_count,
            "target_ceiling": target_ceiling,
            "rate_limit": resolved_rate,
            "concurrency": resolved_concurrency,
            "request_timeout": config_get(config, "nuclei.request_timeout", 8),
            "retries": config_get(config, "nuclei.retries", 0),
            "module_timeout": module_timeout,
            "enforce_module_timeout": enforce_module_timeout,
            "duration_seconds": round(duration, 2),
            "findings_count": 0,
            "targets": target_name,
            "command": cmd,
        }
        _write_nuclei_skip_artifacts(out_dir, metadata)
        skip("Nuclei module skipped")
        info(f"Reason: {reason}")
        print_module_summary(
            "Nuclei Summary",
            {
                "Target": target_name,
                "Duration": f"{duration:.2f}s",
                "Nuclei Status": "Skipped",
                "Reason": reason,
                "Targets": target_count,
            },
        )
        return skipped_result(reason)
    if roi_gate_enabled and baseline_only and not explicit_templates and not selected_tags:
        roi_max_targets = int(config_get(config, "nuclei.roi_gate.max_targets", min(baseline_max_targets or 10, 10)) or 10)
        scoped_domain, scoped_list, roi_target_scope = _scope_baseline_targets_to_roi(
            target_domain,
            target_list,
            output,
            target_name,
            out_dir,
            max_hosts=roi_max_targets,
        )
        roi_scoped_targets = roi_target_scope.get("scoped_targets")
        if roi_scoped_targets is not None and int(roi_scoped_targets or 0) == 0:
            duration = time.perf_counter() - started
            reason = str(roi_target_scope.get("reason") or "baseline-only scan skipped: no ROI-scoped targets")
            metadata = {
                "profile": profile,
                "status": "skipped",
                "skip_reason": reason,
                "severity": resolved_severity,
                "exclude_tags": resolved_exclude_tags,
                "automatic_scan": automatic_scan,
                "baseline_only": baseline_only,
                "detected_technologies": detected_technologies,
                "template_intelligence": template_intelligence,
                "selected_tags_requested": selected_tags_requested,
                "selected_tags": selected_tags,
                "selection_reason": selection_reason,
                "coverage_strategy": "skipped_low_roi_baseline",
                "roi_decision": roi_decision,
                "baseline_reason": reason,
                "baseline_skip_reason": reason,
                "baseline_roi": {"run": False, "reason": reason, "targets": []},
                "baseline_targets": [],
                "target_scope": roi_target_scope,
                "template_candidates": None,
                "template_count_preflight": False,
                "templates_executed": 0,
                "templates_skipped": None,
                "baseline_scan": {
                    "enabled": baseline_enabled,
                    "applied": False,
                    "status": "skipped",
                    "reason": reason,
                    "skip_reason": reason,
                    "roi": {"run": False, "reason": reason, "targets": []},
                    "targets": [],
                    "severity": baseline_severity,
                    "tags": baseline_tags,
                    "max_targets": baseline_max_targets,
                    "template_candidates": None,
                    "templates_executed": 0,
                    "targets_count": 0,
                    "duration_seconds": 0.0,
                },
                "targets_count": 0,
                "target_ceiling": target_ceiling,
                "rate_limit": resolved_rate,
                "concurrency": resolved_concurrency,
                "request_timeout": config_get(config, "nuclei.request_timeout", 8),
                "retries": config_get(config, "nuclei.retries", 0),
                "module_timeout": module_timeout,
                "enforce_module_timeout": enforce_module_timeout,
                "duration_seconds": round(duration, 2),
                "findings_count": 0,
                "targets": target_name,
                "command": cmd,
            }
            _write_nuclei_skip_artifacts(out_dir, metadata)
            skip("Nuclei module skipped")
            info(f"Reason: {reason}")
            return skipped_result(reason)
        if roi_target_scope.get("enabled"):
            cmd = _remove_flag_with_value(cmd, "-l")
            cmd = _remove_flag_with_value(cmd, "-u")
            target_domain = scoped_domain
            target_list = scoped_list
            if target_list:
                cmd += ["-l", str(target_list)]
            elif target_domain:
                cmd += ["-u", str(target_domain)]
            target_count = _count_targets(target_domain, target_list)
            target_scope = roi_target_scope
            selection_reason += "; scoped to validated opportunity hosts"
            info(f"Nuclei baseline-only scope reduced to {target_count} opportunity targets")
        elif roi_target_scope.get("reason"):
            target_scope = roi_target_scope
    baseline_roi: Dict[str, object] = {"run": False, "reason": "not evaluated", "targets": []}
    baseline_skip_reason = ""
    baseline_target_domain = original_target_domain
    baseline_target_list = original_target_list
    baseline_target_count = _count_targets(baseline_target_domain, baseline_target_list)
    if baseline_target_list and target_ceiling and baseline_target_count > target_ceiling:
        raw_targets = [line.strip() for line in baseline_target_list.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
        baseline_capped_file = out_dir / "baseline_targets_capped.txt"
        baseline_capped_file.write_text("\n".join(raw_targets[:target_ceiling]) + "\n", encoding="utf-8")
        baseline_target_list = baseline_capped_file
        baseline_target_domain = None
        baseline_target_count = target_ceiling
    baseline_needed, baseline_reason = _baseline_practicality(baseline_enabled, selected_tags, explicit_templates, baseline_target_count, baseline_max_targets)
    if baseline_needed and roi_gate_enabled and bool(config_get(config, "nuclei.baseline_scan.high_confidence_only", True)):
        baseline_roi_max_targets = int(config_get(config, "nuclei.baseline_scan.max_targets", 50) or 0) or 50
        scoped_baseline_domain, scoped_baseline_list, baseline_roi = _scope_smart_baseline_targets(
            original_target_domain,
            original_target_list,
            target_domain,
            target_list,
            output,
            target_name,
            out_dir,
            max_hosts=baseline_roi_max_targets,
        )
        if baseline_roi.get("run"):
            baseline_target_domain = scoped_baseline_domain
            baseline_target_list = scoped_baseline_list
            baseline_target_count = _count_targets(baseline_target_domain, baseline_target_list)
            baseline_reason = str(baseline_roi.get("reason") or baseline_reason)
        else:
            baseline_needed = False
            baseline_skip_reason = str(baseline_roi.get("reason") or "baseline skipped by opportunity ROI")
            baseline_reason = baseline_skip_reason
    count_templates_before_run = bool(config_get(config, "nuclei.count_templates_before_run", False))
    baseline_cmd = _baseline_target_command(cmd, baseline_target_domain, baseline_target_list)
    baseline_cmd = _replace_flag_value(baseline_cmd, "-severity", baseline_severity)
    baseline_template_candidates = _count_matching_templates(baseline_cmd, timeout=min(module_timeout or 60, 60)) if baseline_needed and count_templates_before_run else None
    template_candidates = _count_matching_templates(cmd, timeout=min(module_timeout or 60, 60)) if count_templates_before_run else None
    tag_fallback_reason = ""
    if selected_tags and not explicit_templates and template_candidates == 0:
        tag_fallback_reason = "Selected intelligence tags matched zero templates; retrying with automatic/profile selection"
        warn(tag_fallback_reason)
        log.warning(tag_fallback_reason)
        cmd = _remove_flag_with_value(cmd, "-tags")
        cmd = _remove_flag_with_value(cmd, "-l")
        cmd = _remove_flag_with_value(cmd, "-u")
        target_domain = original_target_domain
        target_list = original_target_list
        if target_list:
            cmd += ["-l", str(target_list)]
        elif target_domain:
            cmd += ["-u", str(target_domain)]
        selected_tags = []
        target_scope = {"enabled": False, "reason": "tag fallback disabled target scoping"}
        automatic_scan = bool(config_get(config, "nuclei.automatic_scan", False)) and not explicit_templates
        baseline_only = baseline_enabled and not explicit_templates and not automatic_scan
        cmd = _remove_flag_with_value(cmd, "-severity")
        cmd = _remove_flag_with_value(cmd, "-tags")
        if baseline_only:
            resolved_severity = baseline_severity
            cmd += ["-severity", baseline_severity]
            if baseline_tags:
                cmd += ["-tags", baseline_tags]
        if automatic_scan and "-as" not in cmd:
            cmd += ["-as"]
        selection_reason = "intelligence tags unavailable; fallback to automatic scan" if automatic_scan else "intelligence tags unavailable; fallback to baseline-only" if baseline_only else f"intelligence tags unavailable; fallback to profile {profile}"
        template_candidates = _count_matching_templates(cmd, timeout=min(module_timeout or 60, 60)) if count_templates_before_run else None
        baseline_needed = False
        baseline_reason = "tag fallback disabled baseline"
    info(f"Running nuclei profile={profile} severity={resolved_severity} targets={target_name}" + (" automatic-scan=on" if automatic_scan else ""))
    info(f"Template selection reason: {selection_reason}")
    if detected_technologies:
        info(f"Detected technologies: {', '.join(detected_technologies[:8])}")
    if selected_tags:
        info(f"Selected template tags: {', '.join(selected_tags)}")
    info(f"Nuclei targets: {target_count}")
    if template_candidates is not None:
        info(f"Nuclei matching templates before execution: {template_candidates}")
    if baseline_needed:
        info(f"Baseline Nuclei safety net: severity={baseline_severity} targets={baseline_target_count}")
        if baseline_template_candidates is not None:
            info(f"Baseline matching templates before execution: {baseline_template_candidates}")
    log.info("Running command: %s", " ".join(cmd))

    try:
        baseline_status = "not_applicable"
        baseline_stdout = ""
        baseline_stderr = ""
        baseline_templates_executed: Optional[int] = None
        baseline_duration = 0.0
        with log_duration(log, "nuclei"):
            proc = _run_nuclei_process(cmd, module_timeout, out_dir, template_candidates, target_count, enforce_timeout=enforce_module_timeout, progress_interval=progress_interval)

        stdout = proc.stdout or ""
        stderr = _clean_nuclei_output(proc.stderr or "")

        if proc.returncode != 0 and _missing_templates(stderr):
            warn("Nuclei templates missing; updating templates and retrying once")
            log.warning("Nuclei templates missing; attempting template update")
            update_proc = _update_templates(module_timeout or get_timeout("nuclei", 300), default_template_dir)
            update_output = _clean_nuclei_output("\n".join(part for part in (update_proc.stdout, update_proc.stderr) if part.strip()))
            if update_output.strip():
                atomic_write_text(out_dir / "template_update.log", update_output, encoding="utf-8")
            if not _has_templates(default_template_dir):
                reason = f"templates unavailable at {default_template_dir}"
                log.error("nuclei templates unavailable after update attempt: %s", update_output.strip() or reason)
                warn(f"nuclei failed: {reason}")
                return ModuleResult(status="failed", reason=reason)
            if not explicit_templates and _has_templates(default_template_dir) and str(default_template_dir) not in cmd:
                cmd += ["-t", str(default_template_dir)]
            with log_duration(log, "nuclei retry"):
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=module_timeout or None)
            stdout = proc.stdout or ""
            stderr = _clean_nuclei_output(proc.stderr or "")

        if proc.returncode != 0 and not stdout.strip() and selected_tags and not explicit_templates and _no_templates_for_filters(stderr):
            tag_fallback_reason = "Selected intelligence tags failed at runtime; retrying with automatic/profile selection"
            warn(tag_fallback_reason)
            log.warning("%s: %s", tag_fallback_reason, stderr.strip())
            cmd = _remove_flag_with_value(cmd, "-tags")
            cmd = _remove_flag_with_value(cmd, "-l")
            cmd = _remove_flag_with_value(cmd, "-u")
            target_domain = original_target_domain
            target_list = original_target_list
            if target_list:
                cmd += ["-l", str(target_list)]
            elif target_domain:
                cmd += ["-u", str(target_domain)]
            selected_tags = []
            target_scope = {"enabled": False, "reason": "tag fallback disabled target scoping"}
            automatic_scan = bool(config_get(config, "nuclei.automatic_scan", False)) and not explicit_templates
            baseline_only = baseline_enabled and not explicit_templates and not automatic_scan
            cmd = _remove_flag_with_value(cmd, "-severity")
            cmd = _remove_flag_with_value(cmd, "-tags")
            if baseline_only:
                resolved_severity = baseline_severity
                cmd += ["-severity", baseline_severity]
                if baseline_tags:
                    cmd += ["-tags", baseline_tags]
            if automatic_scan and "-as" not in cmd:
                cmd += ["-as"]
            selection_reason = "intelligence tags failed; fallback to automatic scan" if automatic_scan else "intelligence tags failed; fallback to baseline-only" if baseline_only else f"intelligence tags failed; fallback to profile {profile}"
            template_candidates = _count_matching_templates(cmd, timeout=min(module_timeout or 60, 60)) if count_templates_before_run else None
            baseline_needed = False
            with log_duration(log, "nuclei tag fallback retry"):
                proc = _run_nuclei_process(cmd, module_timeout, out_dir, template_candidates, target_count, enforce_timeout=enforce_module_timeout, progress_interval=progress_interval)
            stdout = proc.stdout or ""
            stderr = _clean_nuclei_output(proc.stderr or "")

        if proc.returncode != 0 and not stdout.strip():
            log.error("nuclei failed with exit code %s: %s", proc.returncode, stderr)
            warn(f"nuclei failed (exit code {proc.returncode})")
            console.print(stderr)
            return ModuleResult(status="failed", reason=f"exit code {proc.returncode}")

        if baseline_needed:
            baseline_started = time.perf_counter()
            baseline_status = "completed"
            try:
                with log_duration(log, "nuclei baseline"):
                    baseline_proc = _run_nuclei_process(baseline_cmd, module_timeout, out_dir, baseline_template_candidates, baseline_target_count, enforce_timeout=enforce_module_timeout, progress_interval=progress_interval)
                baseline_stdout = baseline_proc.stdout or ""
                baseline_stderr = _clean_nuclei_output(baseline_proc.stderr or "")
                baseline_templates_executed = _parse_loaded_template_count(baseline_stderr) or baseline_template_candidates
                if baseline_proc.returncode != 0 and not baseline_stdout.strip():
                    baseline_status = "failed"
                    log.warning("nuclei baseline failed with exit code %s: %s", baseline_proc.returncode, baseline_stderr.strip())
            except subprocess.TimeoutExpired:
                baseline_status = "timed_out"
                log.warning("nuclei baseline timed out")
            except Exception as exc:
                baseline_status = "failed"
                log.warning("nuclei baseline failed: %s", exc)
            baseline_duration = time.perf_counter() - baseline_started
            if baseline_stdout.strip():
                stdout = _dedupe_jsonl_text("\n".join(part for part in (stdout, baseline_stdout) if part.strip()))
            if baseline_stderr.strip():
                stderr = "\n".join(part for part in (stderr, baseline_stderr) if part.strip())

        # Write outputs
        _write_results(out_dir, stdout)
        if stderr.strip():
            atomic_write_text(out_dir / "stderr.log", stderr, encoding="utf-8")
        log.info("nuclei completed with exit code %s", proc.returncode)
        findings, _ = _parse_jsonl(stdout)
        loaded_templates = _parse_loaded_template_count(stderr)
        templates_executed = loaded_templates if loaded_templates is not None else template_candidates
        templates_skipped = None
        if template_candidates is not None and templates_executed is not None:
            templates_skipped = max(0, template_candidates - templates_executed)
        duration = time.perf_counter() - started
        write_json(
            out_dir / "metadata.json",
            {
                "profile": profile,
                "status": "completed",
                "severity": resolved_severity,
                "exclude_tags": resolved_exclude_tags,
                "automatic_scan": automatic_scan,
                "baseline_only": baseline_only,
                "detected_technologies": detected_technologies,
                "template_intelligence": template_intelligence,
                "selected_tags_requested": selected_tags_requested,
                "selected_tags": selected_tags,
                "selection_reason": selection_reason,
                "coverage_strategy": "smart_tags_plus_lightweight_baseline" if baseline_needed else "baseline_only" if baseline_only else selection_reason,
                "tag_fallback_reason": tag_fallback_reason,
                "baseline_reason": baseline_reason,
                "baseline_skip_reason": baseline_skip_reason,
                "baseline_roi": baseline_roi,
                "baseline_targets": baseline_roi.get("targets", []) if isinstance(baseline_roi, dict) else [],
                "target_scope": target_scope,
                "template_candidates": template_candidates,
                "template_count_preflight": count_templates_before_run,
                "templates_executed": templates_executed,
                "templates_skipped": templates_skipped,
                "baseline_scan": {
                    "enabled": baseline_enabled,
                    "applied": baseline_needed,
                    "status": baseline_status,
                    "reason": baseline_reason,
                    "skip_reason": baseline_skip_reason,
                    "roi": baseline_roi,
                    "targets": baseline_roi.get("targets", []) if isinstance(baseline_roi, dict) else [],
                    "severity": baseline_severity,
                    "tags": baseline_tags,
                    "max_targets": baseline_max_targets,
                    "template_candidates": baseline_template_candidates,
                    "templates_executed": baseline_templates_executed,
                    "targets_count": baseline_target_count if baseline_needed else 0,
                    "duration_seconds": round(baseline_duration, 2),
                },
                "targets_count": target_count,
                "target_ceiling": target_ceiling,
                "rate_limit": resolved_rate,
                "concurrency": resolved_concurrency,
                "request_timeout": config_get(config, "nuclei.request_timeout", 8),
                "retries": config_get(config, "nuclei.retries", 0),
                "module_timeout": module_timeout,
                "enforce_module_timeout": enforce_module_timeout,
                "duration_seconds": round(duration, 2),
                "findings_count": len(findings),
                "targets": target_name,
                "command": cmd,
            },
        )
        counts = _severity_counts(findings)
        severity_summary = ", ".join(f"{sev}={counts[sev]}" for sev in SEVERITY_ORDER if counts[sev])
        success("Nuclei complete" + (f": {severity_summary}" if severity_summary else ": 0 findings"))
        print_module_summary(
            "Nuclei Summary",
            {
                "Target": target_name,
                "Duration": f"{time.perf_counter() - started:.2f}s",
                "Profile": profile,
                "Automatic Scan": "on" if automatic_scan else "off",
                "Selection Reason": selection_reason,
                "Coverage Strategy": "Smart + baseline" if baseline_needed else selection_reason,
                "Templates Matched": template_candidates if template_candidates is not None else "Unknown",
                "Templates Executed": templates_executed if templates_executed is not None else "Not Run",
                "Templates Skipped": templates_skipped if templates_skipped is not None else "Not Run",
                "Targets": target_count,
                "Rate Limit": resolved_rate,
                "Concurrency": resolved_concurrency,
                "Findings": len(findings),
                "Output Location": out_dir,
            },
        )
        return ModuleResult()

    except FileNotFoundError:
        log.exception("nuclei binary not found while executing")
        result = skipped_result("Binary not installed")
        skip("Nuclei module skipped")
        info("Reason: nuclei binary not found in PATH")
        print_module_summary(
            "Nuclei Summary",
            {
                "Target": target_name,
                "Duration": f"{time.perf_counter() - started:.2f}s",
                "Nuclei Status": "Skipped",
                "Reason": result.reason,
            },
        )
        return result
    except subprocess.TimeoutExpired:
        effective_timeout = module_timeout or get_timeout("nuclei", 300)
        log.error("nuclei timed out after %d seconds", effective_timeout)
        duration = time.perf_counter() - started
        write_json(
            out_dir / "metadata.json",
            {
                "profile": profile,
                "severity": resolved_severity,
                "exclude_tags": resolved_exclude_tags,
                "automatic_scan": automatic_scan,
                "baseline_only": baseline_only if "baseline_only" in locals() else False,
                "selected_tags_requested": selected_tags_requested,
                "selected_tags": selected_tags,
                "selection_reason": selection_reason,
                "coverage_strategy": "smart_tags_plus_lightweight_baseline" if "baseline_needed" in locals() and baseline_needed else "baseline_only" if "baseline_only" in locals() and baseline_only else selection_reason,
                "tag_fallback_reason": tag_fallback_reason,
                "baseline_reason": baseline_reason if "baseline_reason" in locals() else "not evaluated",
                "baseline_skip_reason": baseline_skip_reason if "baseline_skip_reason" in locals() else "",
                "baseline_roi": baseline_roi if "baseline_roi" in locals() else {"run": False, "reason": "not evaluated", "targets": []},
                "baseline_targets": baseline_roi.get("targets", []) if "baseline_roi" in locals() and isinstance(baseline_roi, dict) else [],
                "target_scope": target_scope if "target_scope" in locals() else None,
                "template_candidates": template_candidates if "template_candidates" in locals() else None,
                "baseline_scan": {
                    "enabled": baseline_enabled if "baseline_enabled" in locals() else bool(config_get(config, "nuclei.baseline_scan.enabled", True)),
                    "applied": baseline_needed if "baseline_needed" in locals() else False,
                    "status": "timed_out" if "baseline_needed" in locals() and baseline_needed else "not_applicable",
                    "reason": baseline_reason if "baseline_reason" in locals() else "not evaluated",
                    "skip_reason": baseline_skip_reason if "baseline_skip_reason" in locals() else "",
                    "roi": baseline_roi if "baseline_roi" in locals() else {"run": False, "reason": "not evaluated", "targets": []},
                    "targets": baseline_roi.get("targets", []) if "baseline_roi" in locals() and isinstance(baseline_roi, dict) else [],
                    "severity": baseline_severity if "baseline_severity" in locals() else str(config_get(config, "nuclei.baseline_scan.severity", "critical,high") or "critical,high"),
                    "tags": baseline_tags if "baseline_tags" in locals() else str(config_get(config, "nuclei.baseline_scan.tags", "cve,exposure,misconfig") or ""),
                    "max_targets": baseline_max_targets if "baseline_max_targets" in locals() else int(config_get(config, "nuclei.baseline_scan.max_targets", 50) or 0),
                    "template_candidates": baseline_template_candidates if "baseline_template_candidates" in locals() else None,
                    "templates_executed": None,
                    "targets_count": baseline_target_count if "baseline_target_count" in locals() and baseline_needed else 0,
                    "duration_seconds": 0,
                },
                "targets_count": target_count if "target_count" in locals() else None,
                "rate_limit": resolved_rate,
                "concurrency": resolved_concurrency,
                "request_timeout": config_get(config, "nuclei.request_timeout", 8),
                "retries": config_get(config, "nuclei.retries", 0),
                "duration_seconds": round(duration, 2),
                "timeout_seconds": effective_timeout,
                "status": "timed_out",
                "command": cmd,
            },
        )
        warn(f"nuclei timed out after {effective_timeout}s; continuing")
        return ModuleResult(status="timed_out", reason=f"timeout after {effective_timeout}s")
    except Exception as exc:
        log.exception("Error running nuclei")
        warn(f"Error running nuclei: {exc}")
        return ModuleResult(status="failed", reason=str(exc))


if __name__ == "__main__":
    run(domain="example.com")
