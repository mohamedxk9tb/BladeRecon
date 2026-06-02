"""Advanced recon expansion layer for BladeRecon.

Adds low-noise historical URL intelligence, security-header asset extraction,
focused content discovery, historical JavaScript correlation, and asset
prioritization. The module is intentionally bounded by safety-profile ceilings
so it improves coverage without becoming a generic brute-force scanner.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

import httpx

from .endpoints import _extract_endpoint_items
from .utils import (
    AsyncRateLimiter,
    ModuleResult,
    async_retry,
    config_get,
    dedupe_preserve_order,
    get_profiled_ceiling,
    get_profiled_concurrency,
    get_profiled_rate_limit,
    host_key,
    httpx_client_kwargs,
    info,
    limit_items_with_notice,
    load_config,
    log_duration,
    normalize_scan_profile,
    normalize_url,
    prepare_module_output,
    print_module_summary,
    setup_logging,
    skipped_result,
    success,
    target_output_dir,
    warn,
    write_json,
    write_jsonl,
)


INTERESTING_CONTENT_WORDS = [
    "admin",
    "login",
    "dashboard",
    "panel",
    "internal",
    "backup",
    "staging",
    "test",
    "debug",
]

SECURITY_HEADER_NAMES = {
    "content-security-policy",
    "content-security-policy-report-only",
    "x-content-security-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "referrer-policy",
    "access-control-allow-origin",
    "access-control-allow-headers",
    "access-control-allow-methods",
}

HOST_RE = re.compile(r"(?:(?:https?|wss?)://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?", re.IGNORECASE)
JS_RE = re.compile(r"(?:https?://[^\s\"'<>]+?\.js(?:\?[^\s\"'<>]*)?|/[A-Za-z0-9._~:/@!$&()*+,;=%-]+?\.js(?:\?[^\s\"'<>]*)?)", re.IGNORECASE)


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


def _target_host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return (parsed.hostname or target).lower().rstrip(".")


def _in_scope_host(host: str, root: str) -> bool:
    value = host.lower().rstrip(".")
    return value == root or value.endswith(f".{root}")


def _normalize_historical_url(value: str, root: str) -> str:
    raw = str(value or "").strip().strip("\"'")
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"https://{raw.lstrip('/')}")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    host = (parsed.hostname or "").lower().rstrip(".")
    if not _in_scope_host(host, root):
        return ""
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", parsed.query, ""))


def _path_key(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://example.invalid{value if value.startswith('/') else '/' + value}")
    path = parsed.path or "/"
    path = re.sub(r"/v\d+/", "/v{n}/", path, flags=re.IGNORECASE)
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    return path.rstrip("/") or "/"


def _extract_parameters(urls: Iterable[str]) -> List[str]:
    params: Set[str] = set()
    for url in urls:
        for key in parse_qs(urlparse(url).query).keys():
            if key.strip():
                params.add(key.strip())
    return sorted(params, key=str.lower)


def _extract_endpoint_rows(urls: Iterable[str], source: str = "historical-url") -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    seen: Set[str] = set()
    for url in urls:
        parsed = urlparse(url)
        path = parsed.path or ""
        if not path or path == "/":
            continue
        if any(token in path.lower() for token in ("/api", "/v1", "/v2", "/v3", "graphql", "swagger", "openapi", "auth", "admin", "login")):
            key = url.lower()
            if key not in seen:
                seen.add(key)
                rows.append({"endpoint": url, "source": source, "category": _historical_endpoint_category(url)})
    return rows


def _historical_endpoint_category(url: str) -> str:
    value = url.lower()
    if "graphql" in value:
        return "GraphQL"
    if "swagger" in value or "openapi" in value:
        return "Swagger/OpenAPI"
    if "admin" in value:
        return "Admin"
    if "auth" in value or "login" in value:
        return "Authentication"
    return "REST"


async def _fetch_wayback(domain: str, config: dict, limiter: AsyncRateLimiter) -> Tuple[List[Dict[str, str]], int]:
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        await limiter.wait()
        async with httpx.AsyncClient(timeout=float(config_get(config, "timeouts.source", 30)), follow_redirects=True, **httpx_client_kwargs(config)) as client:
            resp = await async_retry(client.get, url, max_retries=1, delay=1.0, backoff=2.0)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        warn(f"Wayback historical URLs unavailable: {exc}")
        return [], 1
    rows = []
    if isinstance(data, list):
        for entry in data[1:] if data and isinstance(data[0], list) else data:
            value = entry[0] if isinstance(entry, list) and entry else entry if isinstance(entry, str) else ""
            if value:
                rows.append({"url": str(value), "source": "wayback"})
    return rows, 1


async def _fetch_commoncrawl(domain: str, config: dict, limiter: AsyncRateLimiter) -> Tuple[List[Dict[str, str]], int]:
    requests = 0
    timeout = float(config_get(config, "timeouts.source", 30))
    try:
        await limiter.wait()
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, **httpx_client_kwargs(config)) as client:
            requests += 1
            index_resp = await async_retry(client.get, "https://index.commoncrawl.org/collinfo.json", max_retries=1, delay=1.0, backoff=2.0)
            index_resp.raise_for_status()
            indexes = index_resp.json()
            cdx_api = ""
            if isinstance(indexes, list):
                for item in indexes:
                    if isinstance(item, dict) and item.get("cdx-api"):
                        cdx_api = str(item["cdx-api"])
                        break
            if not cdx_api:
                return [], requests
            await limiter.wait()
            requests += 1
            query = f"{cdx_api}?url=*.{domain}/*&output=json&fl=url&filter=status:200&collapse=urlkey&limit=5000"
            resp = await async_retry(client.get, query, max_retries=1, delay=1.0, backoff=2.0)
            resp.raise_for_status()
    except Exception as exc:
        warn(f"Common Crawl historical URLs unavailable: {exc}")
        return [], requests
    rows = []
    for line in resp.text.splitlines():
        try:
            item = json.loads(line)
            if isinstance(item, dict) and item.get("url"):
                rows.append({"url": str(item["url"]), "source": "commoncrawl"})
        except Exception:
            continue
    return rows, requests


async def _fetch_otx_urls(domain: str, config: dict, limiter: AsyncRateLimiter) -> Tuple[List[Dict[str, str]], int]:
    api_key = config_get(config, "api_keys.alienvault") or config.get("alienvault_api_key")
    if not bool(config_get(config, "advanced.historical.sources.alienvault", True)):
        return [], 0
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page=1"
    try:
        kwargs = httpx_client_kwargs(config)
        headers = kwargs.pop("headers", {})
        if api_key:
            headers["X-OTX-API-KEY"] = str(api_key)
        await limiter.wait()
        async with httpx.AsyncClient(timeout=float(config_get(config, "timeouts.source", 30)), headers=headers, **kwargs) as client:
            resp = await async_retry(client.get, url, max_retries=1, delay=1.0, backoff=2.0)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        warn(f"AlienVault historical URLs unavailable: {exc}")
        return [], 1
    rows = []
    candidates = data.get("url_list", []) if isinstance(data, dict) else []
    for item in candidates:
        if isinstance(item, dict):
            value = item.get("url") or item.get("result", {}).get("url")
            if value:
                rows.append({"url": str(value), "source": "alienvault"})
    return rows, 1


def _local_historical_url_rows(target_dir: Path) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for path, source in (
        (target_dir / "endpoints" / "endpoints.json", "endpoint-discovery"),
        (target_dir / "js" / "js_files.json", "javascript"),
        (target_dir / "probe" / "probe.json", "probe"),
        (target_dir / "parameters" / "parameters_from_urls.txt", "parameters"),
    ):
        if not path.exists():
            continue
        if path.suffix == ".txt":
            for line in _read_lines(path):
                rows.append({"url": line, "source": source})
            continue
        data = _read_json(path, [])
        for item in data if isinstance(data, list) else []:
            if isinstance(item, dict):
                for key in ("endpoint", "url", "final_url", "source", "source_page"):
                    if item.get(key):
                        rows.append({"url": str(item[key]), "source": source})
    return rows


async def collect_historical(target: str, output: Path, config: dict, profile: str, resume: bool = False) -> Tuple[Dict[str, Any], int]:
    domain = _target_host(target)
    target_dir = target_output_dir(output, target)
    out_dir = prepare_module_output(output, target, "historical", resume=resume)
    limiter = AsyncRateLimiter(get_profiled_rate_limit("advanced_sources", 1.0, profile, config))
    requests = 0
    source_rows: List[Dict[str, str]] = []
    source_rows.extend(_local_historical_url_rows(target_dir))
    tasks = []
    sources_cfg = config_get(config, "advanced.historical.sources", {})
    if isinstance(sources_cfg, dict) and sources_cfg.get("wayback", True):
        tasks.append(_fetch_wayback(domain, config, limiter))
    if isinstance(sources_cfg, dict) and sources_cfg.get("commoncrawl", True):
        tasks.append(_fetch_commoncrawl(domain, config, limiter))
    if isinstance(sources_cfg, dict) and sources_cfg.get("alienvault", True):
        tasks.append(_fetch_otx_urls(domain, config, limiter))
    for result_rows, count in await asyncio.gather(*tasks, return_exceptions=False) if tasks else []:
        source_rows.extend(result_rows)
        requests += count

    max_urls = get_profiled_ceiling("historical_urls", int(config_get(config, "advanced.historical.max_urls", 1000)), profile, config)
    normalized: Dict[str, Set[str]] = {}
    for row in source_rows:
        url = _normalize_historical_url(str(row.get("url") or ""), domain)
        if not url:
            continue
        normalized.setdefault(url, set()).add(str(row.get("source") or "unknown"))
    urls = sorted(normalized, key=str.lower)
    urls, skipped = limit_items_with_notice(urls, max_urls, "Historical URL intelligence")
    parameters = _extract_parameters(urls)
    endpoints = _extract_endpoint_rows(urls)
    attribution = [{"url": url, "sources": sorted(normalized.get(url, []))} for url in urls]
    (out_dir / "urls.txt").write_text("\n".join(urls), encoding="utf-8")
    (out_dir / "parameters.txt").write_text("\n".join(parameters), encoding="utf-8")
    (out_dir / "endpoints.txt").write_text("\n".join(row["endpoint"] for row in endpoints), encoding="utf-8")
    write_json(out_dir / "urls.json", attribution)
    write_json(out_dir / "endpoints.json", endpoints)
    metadata = {
        "sources": sorted({source for row in attribution for source in row["sources"]}),
        "urls": len(urls),
        "parameters": len(parameters),
        "endpoints": len(endpoints),
        "requests_sent": requests,
        "ceiling": max_urls,
        "ceiling_skipped": skipped,
        "safety_profile": profile,
    }
    write_json(out_dir / "metadata.json", metadata)
    return metadata, requests


def correlate_historical(target: str, output: Path) -> Dict[str, Any]:
    target_dir = target_output_dir(output, target)
    current_rows = _read_json(target_dir / "endpoints" / "endpoints.json", [])
    current_endpoints = [str(row.get("endpoint") or "") for row in current_rows if isinstance(row, dict)]
    historical_rows = _read_json(target_dir / "historical" / "endpoints.json", [])
    historical_endpoints = [str(row.get("endpoint") or "") for row in historical_rows if isinstance(row, dict)]
    alive_hosts = {host_key(url) for url in _read_lines(target_dir / "probe" / "alive.txt")}
    current_keys = {_path_key(url): url for url in current_endpoints}
    historical_keys = {_path_key(url): url for url in historical_endpoints}
    removed = [historical_keys[key] for key in sorted(set(historical_keys) - set(current_keys))]
    legacy = []
    for key, url in historical_keys.items():
        path = urlparse(url).path.lower()
        if re.search(r"/v[0-9]+/", path):
            legacy.append(url)
        elif any(token in path for token in ("legacy", "old", "deprecated", "backup")):
            legacy.append(url)
    deprecated = [url for url in historical_endpoints if any(token in url.lower() for token in ("deprecated", "legacy", "/v1/", "old"))]
    forgotten = dedupe_preserve_order([*removed, *legacy])[:50]
    currently_alive = [url for url in forgotten if host_key(url) in alive_hosts]
    historical_only = [url for url in forgotten if host_key(url) not in alive_hosts and host_key(url)]
    unresolved = [url for url in forgotten if not host_key(url)]
    diff = {
        "current_endpoint_count": len(current_endpoints),
        "historical_endpoint_count": len(historical_endpoints),
        "removed_apis": dedupe_preserve_order(removed),
        "deprecated_endpoints": dedupe_preserve_order(deprecated),
        "legacy_paths": dedupe_preserve_order(legacy),
        "potentially_forgotten_assets": forgotten,
        "historical_and_currently_alive": currently_alive,
        "historical_only": historical_only,
        "historical_unresolved": unresolved,
    }
    write_json(target_dir / "historical_diff.json", diff)
    return diff


def _candidate_content_paths(target_dir: Path, config: dict) -> List[str]:
    words = list(INTERESTING_CONTENT_WORDS)
    tech_rows = _read_json(target_dir / "technologies" / "technologies.json", [])
    text = json.dumps(tech_rows).lower()
    if "wordpress" in text:
        words.extend(["wp-admin", "wp-login.php"])
    if "swagger" in text or "openapi" in text:
        words.extend(["swagger", "swagger-ui", "openapi.json"])
    configured = config_get(config, "advanced.content_discovery.words", [])
    if isinstance(configured, list):
        words.extend(str(item).strip("/") for item in configured if str(item).strip())
    paths = []
    for word in dedupe_preserve_order(words):
        if not word:
            continue
        paths.append("/" + word.strip("/"))
    return dedupe_preserve_order(paths)


async def run_content_discovery(target: str, output: Path, config: dict, profile: str, resume: bool = False) -> Tuple[Dict[str, Any], int]:
    target_dir = target_output_dir(output, target)
    out_dir = prepare_module_output(output, target, "content_discovery", resume=resume)
    alive_hosts = _read_lines(target_dir / "probe" / "alive.txt")
    max_hosts = int(config_get(config, "advanced.content_discovery.max_hosts", 8) or 8)
    hosts = alive_hosts[:max_hosts]
    paths = _candidate_content_paths(target_dir, config)
    ceiling = get_profiled_ceiling("content_discovery", int(config_get(config, "advanced.content_discovery.max_requests", 80)), profile, config)
    candidates = [urljoin(host.rstrip("/") + "/", path.lstrip("/")) for host in hosts for path in paths]
    candidates, skipped = limit_items_with_notice(candidates, ceiling, "Content discovery requests")
    limiter = AsyncRateLimiter(get_profiled_rate_limit("content_discovery", 2.0, profile, config))
    concurrency = get_profiled_concurrency("content_discovery", 4, profile, config)
    sem = asyncio.Semaphore(max(1, concurrency))
    baseline_lengths: Dict[str, int] = {}
    found: List[Dict[str, Any]] = []
    requests = 0
    timeout = float(config_get(config, "timeouts.http", 10))

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False, **httpx_client_kwargs(config)) as client:
        async def baseline(host: str) -> None:
            nonlocal requests
            await limiter.wait()
            requests += 1
            try:
                resp = await client.get(urljoin(host.rstrip("/") + "/", "__bladerecon_missing_probe__"))
                baseline_lengths[host_key(host)] = len(resp.content)
            except Exception:
                baseline_lengths[host_key(host)] = 0

        await asyncio.gather(*(baseline(host) for host in hosts), return_exceptions=True)

        async def check(url: str) -> None:
            nonlocal requests
            async with sem:
                await limiter.wait()
                requests += 1
                try:
                    resp = await async_retry(client.get, url, max_retries=0)
                except Exception:
                    return
                length = len(resp.content)
                base_length = baseline_lengths.get(host_key(url), 0)
                status = int(resp.status_code)
                signal = _content_signal(urlparse(url).path, status)
                if status in {200, 201, 202, 204, 301, 302, 307, 308, 401, 403} and signal["score"] >= 45 and (not base_length or abs(length - base_length) > 64 or status in {401, 403}):
                    found.append(
                        {
                            "url": str(resp.url),
                            "path": urlparse(url).path,
                            "status_code": status,
                            "content_length": length,
                            "signal": signal["level"],
                            "signal_score": signal["score"],
                            "reason": signal["reason"],
                        }
                    )

        await asyncio.gather(*(check(url) for url in candidates), return_exceptions=True)

    found = sorted({row["url"]: row for row in found}.values(), key=lambda item: (-int(item.get("signal_score", 0)), item["url"]))
    (out_dir / "interesting_paths.txt").write_text("\n".join(row["url"] for row in found), encoding="utf-8")
    write_json(out_dir / "interesting_paths.json", found)
    metadata = {
        "hosts": len(hosts),
        "candidate_paths": len(paths),
        "requests_sent": requests,
        "findings": len(found),
        "ceiling": ceiling,
        "ceiling_skipped": skipped,
        "signal_to_noise_ratio": round(len(found) / max(1, requests), 4),
        "safety_profile": profile,
    }
    write_json(out_dir / "metadata.json", metadata)
    return metadata, requests


def _content_signal(path: str, status: int) -> Dict[str, Any]:
    lower = path.lower()
    score = 25
    reasons = []
    if any(token in lower for token in ("admin", "dashboard", "internal", "panel")):
        score += 45
        reasons.append("administrative path keyword")
    if any(token in lower for token in ("login", "auth")):
        score += 30
        reasons.append("authentication path keyword")
    if status in {401, 403}:
        score += 20
        reasons.append("access-controlled response")
    level = "High" if score >= 70 else "Medium" if score >= 45 else "Low"
    return {"level": level, "score": min(100, score), "reason": "; ".join(reasons) or "low-confidence path keyword"}


def _extract_header_assets(headers: Dict[str, str], root: str, source_url: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for name, value in headers.items():
        lower_name = str(name).lower()
        if lower_name not in SECURITY_HEADER_NAMES:
            continue
        for match in HOST_RE.findall(str(value)):
            host = urlparse(match if "://" in match else f"https://{match}").hostname or ""
            if not host:
                continue
            asset_type = "In Scope" if _in_scope_host(host, root) else _classify_external_asset(host)
            rows.append({"asset": host.lower(), "type": asset_type, "header": name, "source": source_url})
    return rows


def _classify_external_asset(host: str) -> str:
    value = host.lower()
    if any(token in value for token in ("auth", "login", "okta", "onelogin", "auth0")):
        return "Authentication"
    if any(token in value for token in ("stripe", "paypal", "checkout", "pay")):
        return "Payment"
    if any(token in value for token in ("cloudfront", "akamai", "fastly", "cloudflare", "cdn")):
        return "CDN"
    if "api" in value:
        return "API"
    return "External"


async def collect_security_header_assets(target: str, output: Path, config: dict, profile: str) -> Tuple[Dict[str, Any], int]:
    root = _target_host(target)
    target_dir = target_output_dir(output, target)
    probe_rows = _read_json(target_dir / "probe" / "probe.json", [])
    assets: List[Dict[str, str]] = []
    requests = 0
    needs_live = []
    for row in probe_rows if isinstance(probe_rows, list) else []:
        if not isinstance(row, dict):
            continue
        headers = row.get("headers") if isinstance(row.get("headers"), dict) else {}
        source = str(row.get("final_url") or row.get("url") or "")
        if headers:
            assets.extend(_extract_header_assets({str(k): str(v) for k, v in headers.items()}, root, source))
        elif source:
            needs_live.append(source)

    ceiling = get_profiled_ceiling("security_header_hosts", int(config_get(config, "advanced.security_headers.max_hosts", 20)), profile, config)
    needs_live, skipped = limit_items_with_notice(dedupe_preserve_order(needs_live), ceiling, "Security header live checks")
    limiter = AsyncRateLimiter(get_profiled_rate_limit("security_headers", 2.0, profile, config))
    timeout = float(config_get(config, "timeouts.http", 10))
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False, **httpx_client_kwargs(config)) as client:
        async def fetch(url: str) -> None:
            nonlocal requests
            await limiter.wait()
            requests += 1
            try:
                resp = await client.get(url)
            except Exception:
                return
            assets.extend(_extract_header_assets({str(k): str(v) for k, v in resp.headers.items()}, root, str(resp.url)))

        await asyncio.gather(*(fetch(url) for url in needs_live), return_exceptions=True)

    deduped = sorted({(row["asset"], row["header"], row["source"]): row for row in assets}.values(), key=lambda item: (item["type"], item["asset"]))
    grouped: Dict[str, int] = {}
    for row in deduped:
        grouped[row["type"]] = grouped.get(row["type"], 0) + 1
    payload = {
        "assets": deduped,
        "summary": grouped,
        "requests_sent": requests,
        "ceiling_skipped": skipped,
        "safety_profile": profile,
    }
    write_json(target_dir / "security_headers_assets.json", payload)
    return payload, requests


async def collect_historical_js(target: str, output: Path, config: dict, profile: str, resume: bool = False) -> Tuple[Dict[str, Any], int]:
    target_dir = target_output_dir(output, target)
    out_dir = prepare_module_output(output, target, "historical_js", resume=resume)
    historical_urls = _read_lines(target_dir / "historical" / "urls.txt")
    live_js_rows = _read_json(target_dir / "js" / "js_files.json", [])
    js_refs: Dict[str, Set[str]] = {}
    for url in historical_urls:
        for match in JS_RE.findall(url):
            normalized = _normalize_historical_url(urljoin(url, match), _target_host(target))
            if normalized:
                js_refs.setdefault(normalized, set()).add("historical-url")
    for row in live_js_rows if isinstance(live_js_rows, list) else []:
        if isinstance(row, dict) and row.get("url"):
            js_refs.setdefault(str(row["url"]), set()).add("live-js")

    ceiling = get_profiled_ceiling("historical_js", int(config_get(config, "advanced.historical_js.max_files", 40)), profile, config)
    js_urls = sorted(js_refs)
    js_urls, skipped = limit_items_with_notice(js_urls, ceiling, "Historical JavaScript analysis")
    limiter = AsyncRateLimiter(get_profiled_rate_limit("historical_js", 2.0, profile, config))
    timeout = float(config_get(config, "timeouts.http", 10))
    requests = 0
    endpoint_rows: List[Dict[str, str]] = []
    parameter_set: Set[str] = set()

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False, **httpx_client_kwargs(config)) as client:
        async def fetch(url: str) -> None:
            nonlocal requests
            await limiter.wait()
            requests += 1
            try:
                resp = await client.get(url)
                resp.raise_for_status()
            except Exception:
                return
            for item in _extract_endpoint_items(resp.text[:500000], url):
                endpoint_rows.append({"endpoint": item["endpoint"], "source": url, "category": item["category"]})
                parameter_set.update(_extract_parameters([item["endpoint"]]))

        await asyncio.gather(*(fetch(url) for url in js_urls), return_exceptions=True)

    endpoint_rows = sorted({row["endpoint"].lower(): row for row in endpoint_rows}.values(), key=lambda item: item["endpoint"])
    (out_dir / "js_urls.txt").write_text("\n".join(js_urls), encoding="utf-8")
    (out_dir / "endpoints.txt").write_text("\n".join(row["endpoint"] for row in endpoint_rows), encoding="utf-8")
    (out_dir / "parameters.txt").write_text("\n".join(sorted(parameter_set, key=str.lower)), encoding="utf-8")
    write_json(out_dir / "js_urls.json", [{"url": url, "sources": sorted(js_refs.get(url, []))} for url in js_urls])
    write_json(out_dir / "endpoints.json", endpoint_rows)
    metadata = {
        "js_files": len(js_urls),
        "endpoints": len(endpoint_rows),
        "parameters": len(parameter_set),
        "requests_sent": requests,
        "ceiling": ceiling,
        "ceiling_skipped": skipped,
        "signal_to_noise_ratio": round(len(endpoint_rows) / max(1, requests), 4),
        "safety_profile": profile,
    }
    write_json(out_dir / "metadata.json", metadata)
    return metadata, requests


def build_asset_priority(target: str, output: Path) -> Dict[str, Any]:
    target_dir = target_output_dir(output, target)
    alive_hosts = _read_lines(target_dir / "probe" / "alive.txt")
    probe_rows = _read_json(target_dir / "probe" / "probe.json", [])
    endpoints = _read_json(target_dir / "endpoints" / "endpoints.json", [])
    historical_diff = _read_json(target_dir / "historical_diff.json", {})
    content_rows = _read_json(target_dir / "content_discovery" / "interesting_paths.json", [])
    nuclei_rows = _read_json(target_dir / "nuclei" / "results.json", [])
    technology_rows = _read_json(target_dir / "technology" / "technology.json", [])
    rows: Dict[str, Dict[str, Any]] = {}

    def ensure(host: str) -> Dict[str, Any]:
        return rows.setdefault(host, {"asset": host, "score": 0, "reasons": [], "signals": {}, "signal_details": []})

    def add_signal(row: Dict[str, Any], name: str, points: int, reason: str, confidence: str = "Medium", detail: str = "") -> None:
        row["score"] += points
        row["reasons"].append(reason)
        row["signals"][name] = int(row["signals"].get(name, 0)) + points
        row["signal_details"].append({"signal": name, "points": points, "confidence": confidence, "reason": reason, "detail": detail})

    for url in alive_hosts:
        host = host_key(url)
        row = ensure(host)
        add_signal(row, "alive_http", 20, "Alive HTTP service", "High", url)
    for item in probe_rows if isinstance(probe_rows, list) else []:
        if not isinstance(item, dict):
            continue
        host = host_key(str(item.get("final_url") or item.get("url") or ""))
        row = ensure(host)
        text = " ".join(str(item.get(key) or "") for key in ("title", "server", "cdn", "waf")).lower()
        if any(token in text for token in ("login", "admin", "dashboard", "portal")):
            add_signal(row, "login_admin_probe", 25, "Login/admin indicator in probe metadata", "High", text[:120])
        if item.get("waf"):
            add_signal(row, "waf_observed", 5, "WAF observed", "Low", str(item.get("waf") or ""))
    for item in endpoints if isinstance(endpoints, list) else []:
        endpoint = str(item.get("endpoint") if isinstance(item, dict) else "")
        host = host_key(endpoint)
        row = ensure(host)
        density_count = int(row["signals"].get("endpoint_count", 0)) + 1
        row["signals"]["endpoint_count"] = density_count
        if density_count <= 10:
            add_signal(row, "endpoint_density", 2, "Endpoint surface observed", "Medium", endpoint)
        if any(token in endpoint.lower() for token in ("admin", "auth", "login", "graphql")):
            add_signal(row, "high_interest_endpoint", 15, "High-interest endpoint", "High", endpoint)
    for item in content_rows if isinstance(content_rows, list) else []:
        url = str(item.get("url") if isinstance(item, dict) else "")
        row = ensure(host_key(url))
        signal_score = int(item.get("signal_score") or (80 if str(item.get("signal") or "") == "High" else 50))
        points = 20 if signal_score >= 70 else 10
        add_signal(row, "interesting_content", points, "Interesting content discovery path", "High" if signal_score >= 70 else "Medium", str(item.get("path") or url))
    for url in historical_diff.get("potentially_forgotten_assets", []) if isinstance(historical_diff, dict) else []:
        row = ensure(host_key(str(url)))
        alive_historical = str(url) in set(historical_diff.get("historical_and_currently_alive", []))
        add_signal(row, "historical_exposure", 16 if alive_historical else 8, "Historical endpoint still tied to live host" if alive_historical else "Historical-only or legacy endpoint", "Medium" if alive_historical else "Low", str(url))
    for item in nuclei_rows if isinstance(nuclei_rows, list) else []:
        if not isinstance(item, dict):
            continue
        host = host_key(str(item.get("host") or item.get("matched") or ""))
        row = ensure(host)
        severity = str(item.get("info", {}).get("severity") or item.get("severity") or "").lower()
        add_signal(row, "nuclei_finding", {"critical": 40, "high": 30, "medium": 18, "low": 8, "info": 3}.get(severity, 5), f"Nuclei {severity or 'unknown'} finding", "High", str(item.get("template") or ""))
    for item in technology_rows if isinstance(technology_rows, list) else []:
        if not isinstance(item, dict):
            continue
        tech_name = str(item.get("name") or "")
        confidence = str(item.get("confidence") or "Medium")
        hosts = item.get("hosts") if isinstance(item.get("hosts"), list) else []
        for host in hosts:
            row = ensure(str(host).lower())
            if tech_name in {"WordPress", "Drupal", "Joomla", "Laravel"} and confidence.lower() in {"medium", "high"}:
                add_signal(row, "technology_interest", 10, "High-interest CMS/framework technology", confidence.title(), tech_name)
            elif tech_name in {"Apache", "Nginx", "IIS", "PHP", "ASP.NET", "Java", "Node.js", "Python"} and confidence.lower() == "high":
                add_signal(row, "technology_interest", 5, "Server/framework technology observed", confidence.title(), tech_name)
    ranked = []
    for row in rows.values():
        row["score"] = min(100, int(row["score"]))
        row["reasons"] = dedupe_preserve_order(row["reasons"])
        row["strongest_factors"] = sorted(row["signal_details"], key=lambda item: (-int(item["points"]), item["signal"]))[:3]
        high_conf = sum(1 for item in row["signal_details"] if item.get("confidence") == "High")
        row["confidence"] = "High" if row["score"] >= 70 and high_conf >= 2 else "Medium" if row["score"] >= 40 or high_conf else "Low"
        ranked.append(row)
    ranked.sort(key=lambda item: (-int(item["score"]), item["asset"]))
    payload = {"assets": ranked, "top_assets": ranked[:10], "asset_count": len(ranked)}
    write_json(target_dir / "asset_priority.json", payload)
    return payload


async def _run_async(target: str, output: Path, profile: str, resume: bool) -> Dict[str, Any]:
    config = load_config()
    historical_meta, historical_requests = await collect_historical(target, output, config, profile, resume=resume)
    diff = correlate_historical(target, output)
    content_meta, content_requests = await run_content_discovery(target, output, config, profile, resume=resume)
    header_assets, header_requests = await collect_security_header_assets(target, output, config, profile)
    historical_js_meta, historical_js_requests = await collect_historical_js(target, output, config, profile, resume=resume)
    priority = build_asset_priority(target, output)
    total_requests = historical_requests + content_requests + header_requests + historical_js_requests
    return {
        "historical": historical_meta,
        "historical_diff": diff,
        "content_discovery": content_meta,
        "security_headers": {"assets": len(header_assets.get("assets", [])), "requests_sent": header_requests},
        "historical_js": historical_js_meta,
        "asset_priority": {"asset_count": priority.get("asset_count", 0), "top_assets": len(priority.get("top_assets", []))},
        "requests_sent": total_requests,
    }


def run(target: str, output: Path = Path("results"), profile: Optional[str] = None, resume: bool = False) -> ModuleResult:
    target_dir = target_output_dir(output, target)
    if not target_dir.exists():
        warn(f"No valid scan found for target: {target}")
        return skipped_result("No valid scan found")
    config = load_config()
    active_profile = normalize_scan_profile(profile, config)
    log = setup_logging(target, output, "advanced")
    started = time.perf_counter()
    info(f"Advanced recon started for {target} profile={active_profile}")
    try:
        with log_duration(log, "advanced"):
            summary = asyncio.run(_run_async(target, output, active_profile, resume))
    except Exception as exc:
        log.exception("Advanced recon failed")
        warn(f"Advanced recon failed: {exc}")
        return ModuleResult(status="failed", reason=str(exc))

    duration = time.perf_counter() - started
    summary["duration_seconds"] = round(duration, 2)
    write_json(target_output_dir(output, target) / "advanced_metadata.json", summary)
    print_module_summary(
        "Advanced Recon Summary",
        {
            "Target": target,
            "Duration": f"{duration:.2f}s",
            "Historical URLs": summary["historical"].get("urls", 0),
            "Historical Endpoints": summary["historical"].get("endpoints", 0),
            "Interesting Paths": summary["content_discovery"].get("findings", 0),
            "Header Assets": summary["security_headers"].get("assets", 0),
            "Historical JS Endpoints": summary["historical_js"].get("endpoints", 0),
            "Priority Assets": summary["asset_priority"].get("asset_count", 0),
            "Requests Sent": summary["requests_sent"],
            "Output Location": target_output_dir(output, target),
        },
    )
    success("Advanced recon layer generated")
    return ModuleResult()
