"""HTTP probe module for alive host detection.

Probes discovered hosts via HTTP/HTTPS to determine which are alive.
Records status codes, page titles, content lengths, and redirect chains.

Outputs:
    results/<domain>/probe/alive.txt   -- newline-separated alive URLs
    results/<domain>/probe/probe.json  -- full JSONL results
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx
from rich.console import Console
console = Console()

from .utils import (
    async_retry,
    AsyncRateLimiter,
    build_headers,
    config_get,
    deduplicate_alive_urls,
    get_concurrency,
    get_profiled_ceiling,
    get_profiled_concurrency,
    get_profiled_per_host_concurrency,
    get_profiled_rate_limit,
    get_timeout,
    httpx_client_kwargs,
    host_key,
    info,
    load_config,
    log_duration,
    normalize_url,
    ProgressReporter,
    limit_items_with_notice,
    normalize_scan_profile,
    prepare_module_output,
    print_module_summary,
    setup_logging,
    success,
    target_output_dir,
    warn,
    write_json,
    write_jsonl,
    get_retries,
)

PROBE_FIELDS = (
    "url", "final_url", "status_code", "title", "content_length",
    "redirects", "alive", "server", "cdn", "waf", "technologies",
    "technology_details", "error",
)

ALIVE_STATUS_CODES = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403}
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_title(html: str) -> str:
    """Extract the ``<title>`` from an HTML document."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        console.print("[red]BeautifulSoup is not installed. Run: pip install beautifulsoup4[/]")
        return ""

    try:
        soup = BeautifulSoup(html, "html.parser")
        tag = soup.find("title")
        return tag.get_text(strip=True) if tag else ""
    except Exception:
        return ""


def _normalize_probe_targets(raw_targets: List[str]) -> List[str]:
    """Return unique HTTP/HTTPS URLs from hosts or URLs."""
    urls: List[str] = []
    for target in raw_targets:
        value = target.strip()
        if not value or value.startswith("#"):
            continue
        if value.startswith(("http://", "https://")):
            urls.append(normalize_url(value))
        else:
            urls.extend([normalize_url(f"https://{value}"), normalize_url(f"http://{value}")])
    return deduplicate_alive_urls(urls)


def _unique_input_hosts(urls: List[str]) -> int:
    hosts = set()
    for url in urls:
        parsed = urlparse(url)
        hosts.add((parsed.hostname or url).lower())
    return len(hosts)


def _result_dict(**kwargs: object) -> Dict[str, object]:
    """Return a probe result dict with all expected keys."""
    defaults: Dict[str, object] = {
        "url": "", "final_url": "", "status_code": 0, "title": "",
        "content_length": 0, "redirects": [], "alive": False, "server": "",
        "cdn": "", "waf": "", "technologies": [], "technology_details": [], "error": "",
    }
    defaults.update(kwargs)
    return {k: defaults[k] for k in PROBE_FIELDS}


def _add_if(haystack: str, tech: List[str], name: str, needles: List[str]) -> None:
    if any(needle in haystack for needle in needles):
        tech.append(name)


def _add_technology_detail(
    details: Dict[str, Dict[str, object]],
    name: str,
    confidence: str,
    source: str,
    evidence: str,
) -> None:
    clean = str(name or "").strip()
    if not clean:
        return
    row = details.setdefault(clean, {"name": clean, "confidence": confidence, "sources": set(), "evidence": set()})
    if _confidence_rank(confidence) > _confidence_rank(str(row.get("confidence") or "")):
        row["confidence"] = confidence
    if source:
        row["sources"].add(source)  # type: ignore[union-attr]
    if evidence:
        row["evidence"].add(evidence[:180])  # type: ignore[union-attr]


def _confidence_rank(value: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(str(value or "").strip().lower(), 0)


def _technology_detail_list(details: Dict[str, Dict[str, object]]) -> List[Dict[str, object]]:
    rows = []
    for row in details.values():
        rows.append(
            {
                "name": row["name"],
                "confidence": row.get("confidence", "Medium"),
                "sources": sorted(row.get("sources", set())),
                "evidence": sorted(row.get("evidence", set())),
            }
        )
    return sorted(rows, key=lambda item: str(item["name"]).lower())


def _generator_meta(html: str) -> str:
    match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        html,
        flags=re.IGNORECASE,
    )
    return match.group(1) if match else ""


def _fingerprint(resp: httpx.Response, title: str, body_text: str = "") -> Dict[str, object]:
    headers = {k.lower(): v for k, v in resp.headers.items()}
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    aspnet_version = headers.get("x-aspnet-version", "")
    via = headers.get("via", "")
    body = body_text[:12000].lower()
    generator = _generator_meta(body_text[:12000]).lower()
    tech: List[str] = []
    details: Dict[str, Dict[str, object]] = {}
    joined = " ".join([
        server,
        powered_by,
        aspnet_version,
        via,
        title,
        generator,
        headers.get("set-cookie", ""),
        headers.get("x-cache", ""),
        headers.get("x-served-by", ""),
        headers.get("x-cdn", ""),
        body,
    ]).lower()

    _add_if(joined, tech, "Nginx", ["nginx"])
    _add_if(joined, tech, "Apache", ["apache"])
    _add_if(joined, tech, "IIS", ["microsoft-iis"])
    _add_if(joined, tech, "LiteSpeed", ["litespeed"])
    _add_if(joined, tech, "ASP.NET Core", ["asp.net core", "aspnetcore", ".aspnetcore"])
    _add_if(joined, tech, "ASP.NET", ["asp.net"])
    _add_if(joined, tech, "PHP", ["php"])
    _add_if(joined, tech, "Laravel", ["laravel_session", "laravel"])
    _add_if(joined, tech, "Django", ["csrftoken", "django"])
    _add_if(joined, tech, "Flask", ["flask"])
    _add_if(joined, tech, "Express.js", ["express"])
    _add_if(joined, tech, "WordPress", ["wp-content", "wp-includes", "wordpress"])
    _add_if(joined, tech, "Drupal", ["drupal"])
    _add_if(joined, tech, "Joomla", ["joomla"])
    _add_if(joined, tech, "React", ["react", "data-reactroot", "__react"])
    _add_if(joined, tech, "Next.js", ["next.js", "__next", "next-route-announcer"])
    _add_if(joined, tech, "Angular", ["ng-version", "angular"])
    _add_if(joined, tech, "Vue", ["vue", "__vue__", "data-v-"])
    _add_if(joined, tech, "Cloudflare", ["cloudflare"])
    _add_if(joined, tech, "Akamai", ["akamai", "akamai-ghost"])
    _add_if(joined, tech, "Fastly", ["fastly"])

    header_checks = [
        ("Nginx", server, "Server Header", "nginx"),
        ("Apache", server, "Server Header", "apache"),
        ("IIS", server, "Server Header", "microsoft-iis"),
        ("LiteSpeed", server, "Server Header", "litespeed"),
        ("ASP.NET", aspnet_version or powered_by, "Framework Header", "asp.net"),
        ("ASP.NET Core", powered_by, "Framework Header", "asp.net core"),
        ("PHP", powered_by or headers.get("set-cookie", ""), "Framework Header", "php"),
        ("Laravel", headers.get("set-cookie", ""), "Cookie Fingerprint", "laravel_session"),
        ("Django", headers.get("set-cookie", ""), "Cookie Fingerprint", "csrftoken"),
        ("Express.js", powered_by, "Framework Header", "express"),
    ]
    for name, value, source, needle in header_checks:
        if needle in str(value or "").lower():
            _add_technology_detail(details, name, "High", source, f"{source}: {str(value)[:80]}")
    header_name_checks = [
        ("ASP.NET", "Framework Header Name", "x-aspnet-version"),
        ("ASP.NET", "Framework Header Name", "x-aspnetmvc-version"),
        ("Drupal", "Framework Header Name", "x-drupal-cache"),
        ("Cloudflare", "CDN Header Name", "cf-ray"),
        ("Cloudflare WAF", "WAF Header Name", "cf-ray"),
        ("CloudFront", "CDN Header Name", "x-amz-cf-id"),
        ("Fastly", "CDN Header Name", "x-served-by"),
        ("LiteSpeed", "Server Header Name", "x-litespeed-cache"),
        ("Sucuri", "WAF Header Name", "x-sucuri-id"),
        ("Imperva", "WAF Header Name", "x-iinfo"),
    ]
    for name, source, header_name in header_name_checks:
        if header_name in headers:
            _add_technology_detail(details, name, "High", source, header_name)
    if generator:
        for name in ("WordPress", "Drupal", "Joomla"):
            if name.lower() in generator:
                _add_technology_detail(details, name, "High", "Generator Meta", f"generator={generator[:80]}")
    body_checks = [
        ("React", ["data-reactroot", "__react"], "High"),
        ("React", ["react"], "Medium"),
        ("Next.js", ["__next", "next-route-announcer", "_next/"], "High"),
        ("Angular", ["ng-version"], "High"),
        ("Angular", ["angular"], "Medium"),
        ("Vue", ["__vue__", "data-v-"], "High"),
        ("Vue", ["vue"], "Medium"),
        ("Drupal", ["drupal-settings-json", "x-drupal-cache"], "High"),
        ("Drupal", ["drupal"], "Medium"),
        ("WordPress", ["wp-content", "wp-includes"], "High"),
        ("WordPress", ["wordpress"], "Medium"),
    ]
    for name, needles, confidence in body_checks:
        matched = next((needle for needle in needles if needle in body), "")
        if matched:
            _add_technology_detail(details, name, confidence, "HTML Fingerprint", matched)

    cdn = ""
    if "cloudflare" in joined or "cf-ray" in headers:
        cdn = "Cloudflare"
        _add_technology_detail(details, "Cloudflare", "High", "CDN Header", "cf-ray" if "cf-ray" in headers else "cloudflare")
    elif "akamai" in joined:
        cdn = "Akamai"
        _add_technology_detail(details, "Akamai", "High", "CDN Header", "akamai")
    elif "cloudfront" in joined or "x-amz-cf-id" in headers:
        cdn = "CloudFront"
        _add_technology_detail(details, "CloudFront", "High", "CDN Header", "x-amz-cf-id")
    elif "fastly" in joined:
        cdn = "Fastly"
        _add_technology_detail(details, "Fastly", "High", "CDN Header", "fastly")

    waf = ""
    if "cf-ray" in headers:
        waf = "Cloudflare"
        _add_technology_detail(details, "Cloudflare WAF", "High", "WAF Header", "cf-ray")
    elif "x-sucuri-id" in headers:
        waf = "Sucuri"
        _add_technology_detail(details, "Sucuri", "High", "WAF Header", "x-sucuri-id")
    elif "x-akamai" in joined or "akamai" in joined:
        waf = "Akamai"
        _add_technology_detail(details, "Akamai WAF", "High", "WAF Header", "akamai")
    elif "x-iinfo" in headers:
        waf = "Imperva"
        _add_technology_detail(details, "Imperva", "High", "WAF Header", "x-iinfo")

    for item in tech:
        _add_technology_detail(details, item, "Low", "Probe Fingerprint", item)
    return {"server": server, "cdn": cdn, "waf": waf, "technologies": sorted(set(tech)), "technology_details": _technology_detail_list(details)}


def _host_from_result(row: Dict[str, object]) -> str:
    value = str(row.get("final_url") or row.get("url") or "")
    parsed = urlparse(value)
    return (parsed.hostname or value).lower().rstrip(".")


def _merge_detected_technology(record: Dict[str, object], name: str, confidence: str, source: str, evidence: str = "") -> None:
    clean = str(name or "").strip()
    if not clean:
        return
    detected = record.setdefault("detected", [])
    if clean.lower() not in {str(item).lower() for item in detected}:  # type: ignore[arg-type]
        detected.append(clean)  # type: ignore[union-attr]
    technologies = record.setdefault("_technologies", {})
    tech_map = technologies  # type: ignore[assignment]
    row = tech_map.setdefault(clean.lower(), {"name": clean, "confidence": confidence, "sources": set(), "evidence": set()})
    if _confidence_rank(confidence) > _confidence_rank(str(row.get("confidence") or "")):
        row["confidence"] = confidence
    if source:
        row["sources"].add(source)
    if evidence:
        row["evidence"].add(evidence[:180])


def _write_technology_outputs(target_dir: Path, results: List[Dict[str, object]]) -> None:
    by_host: Dict[str, Dict[str, object]] = {}
    for row in results:
        host = _host_from_result(row)
        if not host:
            continue
        record = by_host.setdefault(host, {"host": host, "url": row.get("final_url") or row.get("url"), "urls": set(), "detected": []})
        if row.get("final_url") or row.get("url"):
            record["urls"].add(str(row.get("final_url") or row.get("url")))  # type: ignore[union-attr]
        for detail in row.get("technology_details", []) or []:
            if not isinstance(detail, dict):
                continue
            sources = detail.get("sources") if isinstance(detail.get("sources"), list) else [detail.get("source", "Probe Fingerprint")]
            evidence = detail.get("evidence") if isinstance(detail.get("evidence"), list) else [detail.get("evidence", "")]
            _merge_detected_technology(
                record,
                str(detail.get("name") or ""),
                str(detail.get("confidence") or "Medium").title(),
                ", ".join(str(item) for item in sources if item),
                "; ".join(str(item) for item in evidence if item),
            )
        for item in row.get("technologies", []) or []:
            _merge_detected_technology(record, str(item), "Low", "Probe Fingerprint", str(item))
        if row.get("cdn"):
            _merge_detected_technology(record, str(row["cdn"]), "High", "CDN Header", str(row["cdn"]))
        if row.get("waf"):
            _merge_detected_technology(record, f"{row['waf']} WAF", "High", "WAF Header", str(row["waf"]))
        if row.get("server"):
            server = str(row["server"]).split("/")[0].strip()
            _merge_detected_technology(record, server, "High", "Server Header", str(row["server"])[:120])

    records = []
    for record in by_host.values():
        technologies = []
        for item in record.pop("_technologies", {}).values():  # type: ignore[union-attr]
            technologies.append(
                {
                    "name": item["name"],
                    "confidence": item.get("confidence", "Medium"),
                    "sources": sorted(item.get("sources", set())),
                    "evidence": sorted(item.get("evidence", set())),
                }
            )
        detected = sorted({str(item) for item in record.get("detected", []) if str(item).strip()}, key=str.lower)
        if not detected:
            continue
        urls = sorted(record.get("urls", set()))
        records.append({"host": record["host"], "url": record.get("url") or (urls[0] if urls else ""), "urls": urls, "detected": detected, "technologies": sorted(technologies, key=lambda item: str(item["name"]).lower())})
    records.sort(key=lambda item: str(item["host"]).lower())

    out_dir = target_dir / "technologies"
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "technologies.json", records)
    lines: List[str] = []
    for record in records:
        lines.append(f"Host: {record['host']}")
        lines.append("Detected:")
        for item in record.get("technologies", []):
            sources = ", ".join(item.get("sources", [])) or "Probe Fingerprint"
            lines.append(f"- {item['name']} ({item.get('confidence', 'Medium')}) - {sources}")
        lines.append("")
    (out_dir / "technologies.txt").write_text("\n".join(lines).strip(), encoding="utf-8")


async def _browser_probe_url(url: str, timeout: int) -> Dict[str, object]:
    """Use Playwright as a last-mile probe when raw HTTP clients time out."""
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except Exception as exc:
        return _result_dict(url=url, error=f"browser_probe_unavailable:{str(exc)[:120]}")

    browser = None
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
            title = (await page.title())[:200]
            status_code = int(response.status) if response is not None else 0
            headers = await response.all_headers() if response is not None else {}
            final_url = page.url or url
            await context.close()
            await browser.close()
            return _result_dict(
                url=url,
                final_url=final_url,
                status_code=status_code,
                title=title,
                content_length=int(headers.get("content-length") or 0),
                redirects=[final_url] if final_url != url else [],
                alive=bool(status_code and (status_code in ALIVE_STATUS_CODES or 100 <= status_code < 500)),
                server=headers.get("server", ""),
                error="" if status_code else "browser_loaded_without_response",
            )
    except Exception as exc:
        if browser:
            try:
                await browser.close()
            except Exception:
                pass
        return _result_dict(url=url, error=f"browser_probe_failed:{str(exc).splitlines()[0][:160]}")


# ---------------------------------------------------------------------------
# Core probing
# ---------------------------------------------------------------------------

async def _probe_url(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    retries: int,
    limiter: Optional[AsyncRateLimiter] = None,
) -> Dict[str, object]:
    """Send a GET request and return a result dict for *url*."""
    headers_seen = False
    try:
        if limiter:
            await limiter.wait()
        request = client.build_request("GET", url)
        resp = await async_retry(client.send, request, stream=True, follow_redirects=False, max_retries=retries, delay=0.5, backoff=2.0)
        headers_seen = True
        body = b""
        try:
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) >= 12000:
                    break
        except httpx.TimeoutException:
            pass
        finally:
            await resp.aclose()

        text = body.decode(resp.encoding or "utf-8", errors="replace") if body else ""
        title = _extract_title(text[:5000]) if text else ""
        redirects = []
        location = resp.headers.get("location")
        if location:
            redirects.append(str(resp.url.join(location)))
        fp = _fingerprint(resp, title, text)
        status_code = resp.status_code
        return _result_dict(
            url=url,
            final_url=str(resp.url.join(location)) if location else str(resp.url),
            status_code=status_code,
            title=title[:200],
            content_length=int(resp.headers.get("content-length") or len(body) or 0),
            redirects=redirects,
            alive=status_code in ALIVE_STATUS_CODES or 100 <= status_code < 500,
            **fp,
        )
    except httpx.ConnectError:
        return _result_dict(url=url, error="connection_refused")
    except httpx.TimeoutException:
        return _result_dict(url=url, alive=headers_seen, error=f"timeout_after_{timeout}s")
    except Exception as exc:
        return _result_dict(url=url, error=str(exc)[:200])


async def _run_probes(
    urls: List[str],
    dest: Path,
    concurrency: Optional[int] = None,
    timeout: Optional[int] = None,
    proxy: Optional[str] = None,
    user_agent: Optional[str] = None,
    random_user_agent: bool = False,
    resume: bool = False,
    profile: Optional[str] = None,
) -> List[str]:
    """Probe all *urls* and write results to *dest*.

    Returns the list of alive base-URLs (``scheme://host``).
    """
    dest.mkdir(parents=True, exist_ok=True)
    config = load_config()
    active_profile = normalize_scan_profile(profile, config)
    ceiling = get_profiled_ceiling("probe", 500, active_profile, config)
    urls, ceiling_skipped = limit_items_with_notice(urls, ceiling, "Probe requests")
    concurrency = max(1, min(concurrency, max(len(urls), 1)))
    per_host_limit = get_profiled_per_host_concurrency("probe", 2, active_profile, config)
    limiter = AsyncRateLimiter(get_profiled_rate_limit("probe", 12, active_profile, config))
    sem = asyncio.Semaphore(concurrency)
    host_sems: Dict[str, asyncio.Semaphore] = {}
    results: List[Dict[str, object]] = []
    alive_hosts: List[str] = []
    retries = get_retries("http", 1)
    browser_fallback_enabled = bool(config_get(config, "probe.browser_fallback_enabled", True))
    max_browser_fallbacks = max(0, int(config_get(config, "probe.max_browser_fallbacks", 10)))
    reporter = ProgressReporter("Probe", total=len(urls), interval=15)
    reporter.update(0, detail=f"profile={active_profile} concurrency={concurrency} per_host={per_host_limit} rps={limiter.rate_per_second:g} timeout={timeout}s", force=True)
    completed = 0

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=float(timeout),
        verify=False,
        **httpx_client_kwargs(config, proxy, user_agent, random_user_agent),
    ) as client:
        async def _worker(url: str) -> None:
            nonlocal completed
            async with sem:
                host_sem = host_sems.setdefault(host_key(url), asyncio.Semaphore(per_host_limit))
                async with host_sem:
                    r = await _probe_url(client, url, timeout, retries, limiter)
                results.append(r)
                if r["alive"]:
                    alive_hosts.append(r["final_url"])
                completed += 1
                reporter.update(completed, detail=f"alive={len(alive_hosts)}")

        tasks = [asyncio.create_task(_worker(u)) for u in urls]
        await asyncio.gather(*tasks, return_exceptions=True)
    reporter.update(completed, detail=f"alive={len(alive_hosts)}", force=True)

    fallback_urls = [
        str(row.get("url"))
        for row in results
        if not row.get("alive") and str(row.get("error") or "").startswith("timeout_after_")
    ]
    fallback_candidates = len(fallback_urls)
    if fallback_urls and browser_fallback_enabled and max_browser_fallbacks:
        if len(fallback_urls) > max_browser_fallbacks:
            info(f"HTTP probe timed out for {len(fallback_urls)} URL(s); browser fallback capped at {max_browser_fallbacks}")
            fallback_urls = fallback_urls[:max_browser_fallbacks]
        else:
            info(f"HTTP probe timed out for {len(fallback_urls)} URL(s); trying browser fallback")
        replacement = {str(row.get("url")): row for row in results}
        browser_sem = asyncio.Semaphore(min(2, len(fallback_urls)))
        fallback_reporter = ProgressReporter("Probe Browser Fallback", total=len(fallback_urls), interval=10)
        fallback_completed = 0

        async def _browser_worker(url: str) -> None:
            nonlocal fallback_completed
            async with browser_sem:
                row = await _browser_probe_url(url, timeout)
                if row.get("alive"):
                    replacement[url] = row
                elif row.get("error"):
                    existing = replacement.get(url)
                    if existing:
                        existing_error = str(existing.get("error") or "")
                        existing["error"] = f"{existing_error}; {row['error']}" if existing_error else row["error"]
                fallback_completed += 1
                fallback_reporter.update(fallback_completed)

        await asyncio.gather(*(asyncio.create_task(_browser_worker(url)) for url in fallback_urls), return_exceptions=True)
        fallback_reporter.update(fallback_completed, force=True)
        results = [replacement.get(str(row.get("url")), row) for row in results]
        alive_hosts = [str(row.get("final_url")) for row in results if row.get("alive") and row.get("final_url")]
    elif fallback_urls:
        info(f"HTTP probe timed out for {len(fallback_urls)} URL(s); browser fallback disabled or capped at 0")

    # Persist results
    alive_hosts = deduplicate_alive_urls(alive_hosts)
    with open(dest / "alive.txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(alive_hosts))
    write_json(dest / "probe.json", results)
    write_jsonl(dest / "probe.jsonl", results)
    write_json(
        dest / "metadata.json",
        {
            "input_urls": len(urls),
            "input_hosts": _unique_input_hosts(urls),
            "http_requests": len(urls),
            "http_timeout": timeout,
            "http_retries": retries,
            "concurrency": concurrency,
            "per_host_concurrency": per_host_limit,
            "rate_limit_per_second": limiter.rate_per_second,
            "safety_profile": active_profile,
            "request_ceiling": ceiling,
            "ceiling_skipped": ceiling_skipped,
            "browser_fallback_candidates": fallback_candidates,
            "browser_fallback_attempted": len(fallback_urls) if fallback_candidates else 0,
            "browser_fallback_enabled": browser_fallback_enabled,
            "alive_hosts": len(alive_hosts),
        },
    )
    _write_technology_outputs(dest.parent, results)

    return alive_hosts


# ---------------------------------------------------------------------------
# Pipeline / CLI entry points
# ---------------------------------------------------------------------------

def run(
    domain: Optional[str] = None,
    list_file: Optional[Path] = None,
    output: Path = Path("results"),
    concurrency: int = 20,
    timeout: int = 10,
    proxy: Optional[str] = None,
    user_agent: Optional[str] = None,
    random_user_agent: bool = False,
    resume: bool = False,
    profile: Optional[str] = None,
) -> List[str]:
    """Run HTTP probing and return a list of alive URLs.

    Provide either *domain* (reads ``subdomains.txt`` from the standard
    output structure) or *list_file* (arbitrary URLs, one per line).
    """
    urls: List[str] = []
    target_name: str = "probe"

    if list_file:
        if not list_file.exists():
            warn(f"List file not found: {list_file}")
            return []
        urls = _normalize_probe_targets(list_file.read_text(encoding="utf-8").splitlines())
        target_name = list_file.stem
    elif domain:
        sub_file = target_output_dir(output, domain) / "subdomains" / "subdomains.txt"
        if sub_file.exists():
            subs = [l.strip() for l in sub_file.read_text(encoding="utf-8").splitlines() if l.strip()]
            urls = _normalize_probe_targets(subs)
            target_name = domain
        else:
            urls = _normalize_probe_targets([domain])
            target_name = domain
    else:
        warn("Either --domain or --list is required")
        return []

    dest = prepare_module_output(output, target_name, "probe", resume=resume)
    if not urls:
        warn("No URLs to probe")
        return []
    log = setup_logging(target_name, output, "probe")
    started = time.perf_counter()

    config = load_config()
    active_profile = normalize_scan_profile(profile, config)
    timeout = int(timeout) if timeout is not None else get_timeout("http", 10)
    concurrency = max(1, int(concurrency)) if concurrency is not None else get_profiled_concurrency("probe", get_concurrency("probe", 20), active_profile, config)

    info(f"Probing alive hosts: profile={active_profile} targets={len(urls)} concurrency={concurrency} timeout={timeout}s")
    log.info("Starting probe for %d URLs", len(urls))

    try:
        with log_duration(log, "probe"):
            alive = asyncio.run(_run_probes(urls, dest, concurrency=concurrency, timeout=timeout, proxy=proxy, user_agent=user_agent, random_user_agent=random_user_agent, profile=active_profile))
    except Exception as exc:
        log.exception("Probe failed")
        warn(f"Probe failed: {exc}")
        return []

    success(f"Probe complete: {len(alive)} alive hosts out of {len(urls)} probed")
    success(f"Results: {dest}")
    print_module_summary(
        "Probe Summary",
        {
            "Target": target_name,
            "Duration": f"{time.perf_counter() - started:.2f}s",
            "Input Hosts": _unique_input_hosts(urls),
            "HTTP Requests": len(urls),
            "Alive Hosts": len(alive),
            "Output Location": dest,
        },
    )
    log.info("Probe done: %d alive / %d total", len(alive), len(urls))
    return alive


if __name__ == "__main__":
    run(domain="example.com")
