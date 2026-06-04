"""Subdomain enumeration module.

Sources:
- crt.sh (certificates)
- AlienVault OTX passive DNS
- DNS brute-force using common prefixes

This module exposes a `run` function that the CLI can call.
"""
from __future__ import annotations

import asyncio
import email.utils
import re
import secrets
import socket
import string
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from rich.console import Console

from .utils import (
    config_get,
    deduplicate_prefixes,
    deduplicate_subdomains,
    httpx_client_kwargs,
    info,
    load_cache,
    load_config,
    log_duration,
    prepare_module_output,
    save_cache,
    setup_logging,
    print_module_summary,
    skip,
    success,
    warn,
    write_json,
    write_jsonl,
)

console = Console()

TRANSIENT_SOURCE_STATUSES = {429, 500, 502, 503, 504}
SOURCE_COOLDOWNS: Dict[str, float] = {}


def _is_in_scope(host: str, domain: str) -> bool:
    value = host.strip().lower().rstrip(".")
    root = domain.strip().lower().rstrip(".")
    return value == root or value.endswith(f".{root}")


def _extract_hosts(value: str, domain: str) -> List[str]:
    """Extract in-scope hostnames from JSON/text/HTML/CSV fragments."""
    if not value:
        return []
    pattern = re.compile(rf"(?:[a-zA-Z0-9_-]+\.)+{re.escape(domain.rstrip('.'))}", re.IGNORECASE)
    return [host.lower().rstrip(".") for host in pattern.findall(value) if _is_in_scope(host, domain)]


def _tagged(source: str, subdomains: List[str]) -> List[Dict[str, str]]:
    return [{"subdomain": subdomain, "source": source} for subdomain in deduplicate_subdomains(subdomains)]


def _normalise_cached(source: str, cached: Any) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    if not isinstance(cached, list):
        return rows
    for item in cached:
        if isinstance(item, dict):
            subdomain = str(item.get("subdomain") or "").strip()
            if subdomain:
                rows.append({"subdomain": subdomain, "source": str(item.get("source") or source)})
        elif isinstance(item, str):
            rows.append({"subdomain": item, "source": source})
    return rows


def _log_source_result(source: str, candidates: List[str], tagged: List[Dict[str, str]], log: Optional[Any] = None, cached: bool = False) -> None:
    suffix = " from cache" if cached else ""
    if log:
        log.info("%s returned %d candidates and %d unique tagged subdomains%s", source, len(candidates), len(tagged), suffix)


def _retry_after_seconds(value: str, default: float = 2.0) -> float:
    raw = str(value or "").strip()
    if not raw:
        return default
    try:
        return max(0.0, min(30.0, float(raw)))
    except ValueError:
        try:
            parsed = email.utils.parsedate_to_datetime(raw)
            return max(0.0, min(30.0, parsed.timestamp() - time.time()))
        except Exception:
            return default


async def _source_get(client: httpx.AsyncClient, source: str, url: str, **kwargs: Any) -> httpx.Response:
    now = time.monotonic()
    cooldown_until = SOURCE_COOLDOWNS.get(source, 0.0)
    if cooldown_until > now:
        await asyncio.sleep(cooldown_until - now)
    delay = 1.0
    last_resp: Optional[httpx.Response] = None
    for attempt in range(3):
        resp = await client.get(url, **kwargs)
        if resp.status_code not in TRANSIENT_SOURCE_STATUSES:
            return resp
        last_resp = resp
        wait = _retry_after_seconds(resp.headers.get("retry-after", ""), delay)
        SOURCE_COOLDOWNS[source] = time.monotonic() + wait
        if attempt < 2:
            await asyncio.sleep(wait)
            delay *= 2.0
            continue
        return resp
    return last_resp  # type: ignore[return-value]


async def _fetch_crtsh(domain: str, config: dict, output: Path, proxy: Optional[str] = None, user_agent: Optional[str] = None, random_user_agent: bool = False) -> Optional[List[Dict[str, str]]]:
    cached = load_cache(output, "crtsh", domain)
    if cached is not None:
        rows = _normalise_cached("crtsh", cached)
        _log_source_result("crt.sh", [row.get("subdomain", "") for row in rows], rows, cached=True)
        return rows
    urls = [
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    ]
    data: Any = []
    try:
        async with httpx.AsyncClient(timeout=float(config_get(config, "timeouts.source", 30)), follow_redirects=True, **httpx_client_kwargs(config, proxy, user_agent, random_user_agent)) as client:
            last_error: Optional[Exception] = None
            for url in urls:
                try:
                    resp = await _source_get(client, "crt.sh", url)
                    resp.raise_for_status()
                    data = resp.json()
                    last_error = None
                    break
                except Exception as exc:
                    last_error = exc
            if last_error:
                raise last_error
    except Exception as exc:
        warn(f"crt.sh request failed: {exc}")
        return None

    subs: List[str] = []
    if isinstance(data, list):
        for entry in data:
            name = entry.get("name_value") or ""
            for part in str(name).split("\n"):
                subs.extend(_extract_hosts(part, domain))
    tagged = _tagged("crtsh", subs)
    _log_source_result("crt.sh", subs, tagged)
    save_cache(output, "crtsh", domain, tagged)
    return tagged


async def _fetch_alienvault(domain: str, config: dict, output: Path, api_key: Optional[str] = None, proxy: Optional[str] = None, user_agent: Optional[str] = None, random_user_agent: bool = False) -> Optional[List[Dict[str, str]]]:
    cached = load_cache(output, "alienvault", domain)
    if cached is not None:
        rows = _normalise_cached("alienvault", cached)
        _log_source_result("AlienVault", [row.get("subdomain", "") for row in rows], rows, cached=True)
        return rows
    # AlienVault OTX passive DNS endpoint
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    try:
        kwargs = httpx_client_kwargs(config, proxy, user_agent, random_user_agent)
        headers = {**kwargs.pop("headers", {}), **headers}
        async with httpx.AsyncClient(timeout=float(config_get(config, "timeouts.source", 30)), headers=headers, **kwargs) as client:
            resp = await _source_get(client, "AlienVault", url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        warn(f"AlienVault request failed: {exc}")
        return None

    subs: List[str] = []
    if isinstance(data, dict):
        # Many responses include 'passive_dns' as a list
        for item in data.get("passive_dns", []):
            h = item.get("hostname") or item.get("name")
            subs.extend(_extract_hosts(str(h or ""), domain))
    elif isinstance(data, list):
        for item in data:
            h = item.get("hostname") or item.get("name") or item.get("host")
            subs.extend(_extract_hosts(str(h or ""), domain))

    tagged = _tagged("alienvault", subs)
    _log_source_result("AlienVault", subs, tagged)
    save_cache(output, "alienvault", domain, tagged)
    return tagged


async def _fetch_chaos(domain: str, config: dict, output: Path, proxy: Optional[str] = None, user_agent: Optional[str] = None, random_user_agent: bool = False) -> Optional[List[Dict[str, str]]]:
    cached = load_cache(output, "chaos", domain)
    if cached is not None:
        rows = _normalise_cached("chaos", cached)
        _log_source_result("Chaos", [row.get("subdomain", "") for row in rows], rows, cached=True)
        return rows
    api_key = config_get(config, "api_keys.chaos") or config.get("chaos_api_key")
    if not api_key:
        warn("Chaos API key not configured; skipping Chaos")
        return None
    url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
    try:
        kwargs = httpx_client_kwargs(config, proxy, user_agent, random_user_agent)
        headers = {**kwargs.pop("headers", {}), "Authorization": str(api_key)}
        async with httpx.AsyncClient(timeout=float(config_get(config, "timeouts.source", 30)), headers=headers, **kwargs) as client:
            resp = await _source_get(client, "Chaos", url)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        warn(f"Chaos request failed: {exc}")
        return None
    subs = [_extract_hosts(f"{item}.{domain}", domain)[0] for item in data.get("subdomains", []) if _extract_hosts(f"{item}.{domain}", domain)] if isinstance(data, dict) else []
    tagged = _tagged("chaos", subs)
    _log_source_result("Chaos", subs, tagged)
    save_cache(output, "chaos", domain, tagged)
    return tagged


async def _fetch_bufferover(domain: str, config: dict, output: Path, proxy: Optional[str] = None, user_agent: Optional[str] = None, random_user_agent: bool = False) -> Optional[List[Dict[str, str]]]:
    cached = load_cache(output, "bufferover", domain)
    if cached is not None:
        rows = _normalise_cached("bufferover", cached)
        _log_source_result("BufferOver", [row.get("subdomain", "") for row in rows], rows, cached=True)
        return rows
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    try:
        async with httpx.AsyncClient(timeout=float(config_get(config, "timeouts.source", 30)), follow_redirects=True, **httpx_client_kwargs(config, proxy, user_agent, random_user_agent)) as client:
            resp = await _source_get(client, "BufferOver", url)
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return None
    subs: List[str] = []
    if isinstance(data, dict):
        for key in ("FDNS_A", "RDNS"):
            for item in data.get(key) or []:
                subs.extend(_extract_hosts(str(item), domain))
    tagged = _tagged("bufferover", subs)
    _log_source_result("BufferOver", subs, tagged)
    save_cache(output, "bufferover", domain, tagged)
    return tagged


async def _fetch_urlscan(domain: str, config: dict, output: Path, proxy: Optional[str] = None, user_agent: Optional[str] = None, random_user_agent: bool = False) -> Optional[List[Dict[str, str]]]:
    cached = load_cache(output, "urlscan", domain)
    if cached is not None:
        rows = _normalise_cached("urlscan", cached)
        _log_source_result("URLScan", [row.get("subdomain", "") for row in rows], rows, cached=True)
        return rows
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
    try:
        async with httpx.AsyncClient(timeout=float(config_get(config, "timeouts.source", 30)), follow_redirects=True, **httpx_client_kwargs(config, proxy, user_agent, random_user_agent)) as client:
            resp = await _source_get(client, "URLScan", url)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        warn(f"URLScan request failed: {exc}")
        return None
    subs: List[str] = []
    if isinstance(data, dict):
        for item in data.get("results", []):
            page = item.get("page", {}) if isinstance(item, dict) else {}
            for key in ("domain", "url"):
                subs.extend(_extract_hosts(str(page.get(key) or ""), domain))
    tagged = _tagged("urlscan", subs)
    _log_source_result("URLScan", subs, tagged)
    save_cache(output, "urlscan", domain, tagged)
    return tagged


async def _fetch_plain_text_source(source: str, url: str, domain: str, config: dict, output: Path, proxy: Optional[str], user_agent: Optional[str], random_user_agent: bool) -> Optional[List[Dict[str, str]]]:
    cached = load_cache(output, source, domain)
    if cached is not None:
        rows = _normalise_cached(source, cached)
        _log_source_result(source, [row.get("subdomain", "") for row in rows], rows, cached=True)
        return rows
    try:
        async with httpx.AsyncClient(timeout=float(config_get(config, "timeouts.source", 30)), **httpx_client_kwargs(config, proxy, user_agent, random_user_agent)) as client:
            resp = await _source_get(client, source, url)
            resp.raise_for_status()
    except Exception as exc:
        warn(f"{source} request failed: {exc}")
        return None
    subs = _extract_hosts(resp.text, domain)
    tagged = _tagged(source, subs)
    _log_source_result(source, subs, tagged)
    save_cache(output, source, domain, tagged)
    return tagged


DnsFingerprint = Tuple[str, ...]


async def _resolve_fingerprint(host: str, timeout: float = 3.0, retries: int = 1) -> DnsFingerprint:
    loop = asyncio.get_running_loop()

    def _lookup(h: str) -> DnsFingerprint:
        values = set()
        try:
            _, aliases, ips = socket.gethostbyname_ex(h)
            values.update(f"cname:{alias.lower().rstrip('.')}" for alias in aliases if alias)
            values.update(f"ip:{ip}" for ip in ips if ip)
        except Exception:
            pass
        try:
            for item in socket.getaddrinfo(h, None):
                sockaddr = item[4]
                if sockaddr:
                    values.add(f"ip:{sockaddr[0]}")
        except Exception:
            pass
        return tuple(sorted(values))

    for attempt in range(retries + 1):
        try:
            return await asyncio.wait_for(loop.run_in_executor(None, _lookup, host), timeout=timeout)
        except Exception:
            if attempt >= retries:
                return ()
            await asyncio.sleep(0.1 * (attempt + 1))
    return ()


async def _resolve(host: str, timeout: float = 3.0, retries: int = 1) -> bool:
    return bool(await _resolve_fingerprint(host, timeout=timeout, retries=retries))


async def _dns_brute(domain: str, prefixes: List[str], concurrency: int = 50) -> List[str]:
    sem = asyncio.Semaphore(concurrency)
    found: List[str] = []

    async def worker(prefix: str) -> None:
        host = f"{prefix}.{domain}"
        async with sem:
            ok = await _resolve(host)
            if ok:
                found.append(host)

    tasks = [asyncio.create_task(worker(p)) for p in prefixes]
    await asyncio.gather(*tasks, return_exceptions=True)
    return deduplicate_subdomains(found)


def _random_wildcard_host(domain: str) -> str:
    alphabet = string.ascii_lowercase + string.digits
    label = "".join(secrets.choice(alphabet) for _ in range(12))
    return f"{label}.{domain}"


def _fingerprint_display(fingerprint: DnsFingerprint) -> str:
    values = [item.split(":", 1)[1] for item in fingerprint]
    return ", ".join(values)


async def _detect_wildcard_dns(domain: str, timeout: float = 3.0, retries: int = 1) -> List[DnsFingerprint]:
    hosts = [_random_wildcard_host(domain) for _ in range(3)]
    results = await asyncio.gather(
        *[_resolve_fingerprint(host, timeout=timeout, retries=retries) for host in hosts],
        return_exceptions=True,
    )
    fingerprints: List[DnsFingerprint] = []
    seen = set()
    for item in results:
        if isinstance(item, tuple) and item:
            key = tuple(item)
            if key not in seen:
                seen.add(key)
                fingerprints.append(key)
    return fingerprints


async def _dns_wordlist_expand(
    domain: str,
    prefixes: List[str],
    known_subdomains: List[str],
    concurrency: int = 30,
    timeout: float = 3.0,
    retries: int = 1,
) -> Tuple[List[Dict[str, str]], bool, int, List[str]]:
    """Resolve a small wordlist as a low-noise fallback when passive coverage is low."""
    known = {subdomain.strip().lower().rstrip(".") for subdomain in known_subdomains}
    candidates = [
        f"{prefix}.{domain}".lower().rstrip(".")
        for prefix in prefixes
        if f"{prefix}.{domain}".lower().rstrip(".") not in known
    ]
    queue: asyncio.Queue[str] = asyncio.Queue()
    for candidate in deduplicate_subdomains(candidates):
        queue.put_nowait(candidate)

    found: List[str] = []
    filtered = 0
    wildcard_fingerprints: List[DnsFingerprint] = []
    wildcard_detected = False

    try:
        info("Checking for wildcard DNS...")
        wildcard_fingerprints = await _detect_wildcard_dns(domain, timeout=timeout, retries=retries)
        wildcard_detected = bool(wildcard_fingerprints)
        if wildcard_detected:
            warn("Wildcard DNS detected")
            for fingerprint in wildcard_fingerprints:
                info(f"Wildcard fingerprint: {_fingerprint_display(fingerprint)}")
    except Exception:
        wildcard_fingerprints = []
        wildcard_detected = False

    async def worker() -> None:
        nonlocal filtered
        while True:
            try:
                host = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                fingerprint = await _resolve_fingerprint(host, timeout=timeout, retries=retries)
                if not fingerprint:
                    continue
                if wildcard_detected and fingerprint in wildcard_fingerprints:
                    filtered += 1
                    continue
                if fingerprint:
                    found.append(host)
            finally:
                queue.task_done()

    worker_count = min(max(1, concurrency), max(1, queue.qsize()))
    workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
    await asyncio.gather(*workers, return_exceptions=True)
    return _tagged("wordlist", found), wildcard_detected, filtered, [_fingerprint_display(item) for item in wildcard_fingerprints]


def _read_prefix_file(path: Path) -> List[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def _load_prefixes(config: dict, prefixes_file: Optional[Path]) -> List[str]:
    default_wordlist = Path(__file__).parents[1] / "wordlists" / "subdomains.txt"
    default_prefixes = _read_prefix_file(default_wordlist)
    config_prefixes = config.get("dns_brute_prefixes", [])
    if isinstance(config_prefixes, str):
        config_prefixes = [config_prefixes]
    custom_prefixes = _read_prefix_file(prefixes_file) if prefixes_file else []
    return deduplicate_prefixes([*default_prefixes, *config_prefixes, *custom_prefixes])


def run(domain: str, output: Path, passive: bool = True, active: bool = False, prefixes_file: Optional[Path] = None, proxy: Optional[str] = None, user_agent: Optional[str] = None, random_user_agent: bool = False, resume: bool = False) -> None:
    """Run subdomain enumeration pipeline.

    - passive: use crt.sh and AlienVault
    - active: attempt DNS brute with prefixes
    Results are saved to `output / domain / subdomains / subdomains.txt`.
    """
    out_dir = prepare_module_output(output, domain, "subdomains", resume=resume)
    log = setup_logging(domain, output, "subdomains")
    started = time.perf_counter()

    info(f"Subdomain enumeration started for {domain}")
    log.info("Starting subdomain enumeration for %s", domain)

    config = load_config()
    concurrency = max(1, int(config_get(config, "concurrency.dns", config.get("dns_concurrency", 50))))
    wordlist_threshold = max(0, int(config_get(config, "wordlist_expansion.threshold", 30)))
    wordlist_enabled = bool(config_get(config, "wordlist_expansion.enabled", True))
    wordlist_concurrency = min(50, max(1, int(config_get(config, "wordlist_expansion.concurrency", min(concurrency, 30)))))
    wordlist_timeout = float(config_get(config, "wordlist_expansion.timeout", config_get(config, "timeouts.dns", 3)))
    wordlist_retries = max(0, int(config_get(config, "wordlist_expansion.retries", 1)))
    prefixes = _load_prefixes(config, prefixes_file)

    results: List[Dict[str, str]] = []
    wordlist_results_count = 0
    wildcard_detected = False
    wildcard_filtered_count = 0
    source_status: Dict[str, str] = {}

    async def _run_all() -> None:
        nonlocal wildcard_detected, wildcard_filtered_count, wordlist_results_count
        tasks: List[Tuple[str, asyncio.Task[object]]] = []
        if passive:
            source_tasks = [
                ("crt.sh", "crtsh", lambda: _fetch_crtsh(domain, config, output, proxy, user_agent, random_user_agent)),
                ("AlienVault", "alienvault", lambda: _fetch_alienvault(domain, config, output, api_key=config_get(config, "api_keys.alienvault") or config.get("alienvault_api_key"), proxy=proxy, user_agent=user_agent, random_user_agent=random_user_agent)),
                ("Chaos", "chaos", lambda: _fetch_chaos(domain, config, output, proxy, user_agent, random_user_agent)),
                ("BufferOver", "bufferover", lambda: _fetch_bufferover(domain, config, output, proxy, user_agent, random_user_agent)),
                ("URLScan", "urlscan", lambda: _fetch_urlscan(domain, config, output, proxy, user_agent, random_user_agent)),
                ("RapidDNS", "rapiddns", lambda: _fetch_plain_text_source("rapiddns", f"https://rapiddns.io/subdomain/{domain}?full=1", domain, config, output, proxy, user_agent, random_user_agent)),
                ("Anubis", "anubis", lambda: _fetch_plain_text_source("anubis", f"https://jldc.me/anubis/subdomains/{domain}", domain, config, output, proxy, user_agent, random_user_agent)),
                ("HackerTarget", "hackertarget", lambda: _fetch_plain_text_source("hackertarget", f"https://api.hackertarget.com/hostsearch/?q={domain}", domain, config, output, proxy, user_agent, random_user_agent)),
            ]
            for label, key, factory in source_tasks:
                if bool(config_get(config, f"sources.{key}", False)):
                    if key == "chaos" and not (config_get(config, "api_keys.chaos") or config.get("chaos_api_key")):
                        source_status[label] = "Skipped (API key not configured)"
                        skip(f"{label}: skipped")
                        info("Reason: API key not configured")
                        log.info("%s skipped: API key not configured", label)
                        continue
                    info(f"Running {label}")
                    source_status[label] = "Running"
                    tasks.append((label, asyncio.create_task(factory())))
                else:
                    source_status[label] = "Disabled"

        if active:
            info("Running DNS brute")
            tasks.append(("DNS brute", asyncio.create_task(_dns_brute(domain, prefixes, concurrency=concurrency))))

        if not tasks:
            return

        async def _tracked(name: str, task: asyncio.Task[object]) -> Tuple[str, object]:
            try:
                return name, await task
            except Exception as exc:
                return name, exc

        tracked = [_tracked(name, task) for name, task in tasks]
        for completed in asyncio.as_completed(tracked):
            name, item = await completed
            if isinstance(item, Exception):
                log.error("%s failed: %s", name, item)
                source_status[name] = "Failed"
                warn(f"{name}: source error")
            elif item is None:
                if name == "BufferOver":
                    source_status[name] = "Skipped (unavailable)"
                    skip("BufferOver unavailable")
                else:
                    source_status[name] = "Failed"
                    warn(f"{name}: unavailable")
                log.warning("%s unavailable or failed", name)
            elif isinstance(item, list):
                if item and isinstance(item[0], str):
                    item = _tagged("dns_brute", item)
                results.extend(item)  # type: ignore[arg-type]
                source_status[name] = f"Completed ({len(item)} results)"
                success(f"{name}: {len(item)} results")
                log.info("%s returned %d subdomains", name, len(item))

        passive_subdomains = deduplicate_subdomains(row.get("subdomain", "") for row in results)
        if passive and wordlist_enabled and not active and len(passive_subdomains) < wordlist_threshold:
            info(f"Passive results below threshold ({len(passive_subdomains)} < {wordlist_threshold})")
            info("Starting lightweight DNS expansion")
            log.info("Starting wordlist DNS expansion because %d < %d", len(passive_subdomains), wordlist_threshold)
            wordlist_rows, wildcard_detected, wildcard_filtered_count, _ = await _dns_wordlist_expand(
                domain,
                prefixes,
                passive_subdomains,
                concurrency=wordlist_concurrency,
                timeout=wordlist_timeout,
                retries=wordlist_retries,
            )
            wordlist_results_count = len(deduplicate_subdomains(row.get("subdomain", "") for row in wordlist_rows))
            results.extend(wordlist_rows)
            success(f"Wordlist expansion found {wordlist_results_count} subdomains")
            if wildcard_filtered_count:
                info(f"Filtered wildcard results: {wildcard_filtered_count}")
            log.info("Wordlist expansion returned %d subdomains", wordlist_results_count)
        elif passive and wordlist_enabled:
            info(f"Passive results met threshold ({len(passive_subdomains)} >= {wordlist_threshold}); skipping DNS expansion")
            log.info("Skipping wordlist DNS expansion because %d >= %d", len(passive_subdomains), wordlist_threshold)

    try:
        with log_duration(log, "subdomains"):
            asyncio.run(_run_all())
    except Exception as exc:
        log.exception("Enumeration failed")
        console.log(f"[red]Enumeration failed:[/] {exc}")

    subdomains = deduplicate_subdomains(row.get("subdomain", "") for row in results)
    passive_results_count = len(deduplicate_subdomains(row.get("subdomain", "") for row in results if row.get("source") not in {"dns_brute", "wordlist"}))
    info(f"Final deduplicated count: {len(subdomains)}")
    log.info("Deduplicated to %d unique subdomains", len(subdomains))
    source_rows = []
    seen_rows = set()
    for row in results:
        subdomain = row.get("subdomain", "").strip().lower()
        source = row.get("source", "unknown")
        if subdomain in subdomains and (subdomain, source) not in seen_rows:
            seen_rows.add((subdomain, source))
            source_rows.append({"subdomain": subdomain, "source": source})

    if subdomains:
        out_file = out_dir / "subdomains.txt"
        out_file.write_text("\n".join(subdomains), encoding="utf-8")
        write_json(out_dir / "subdomains.json", [{"subdomain": subdomain, "sources": sorted({row["source"] for row in source_rows if row["subdomain"] == subdomain})} for subdomain in subdomains])
        write_jsonl(out_dir / "subdomains.jsonl", source_rows)
        log.info("Saved %d subdomains to %s", len(subdomains), out_file)
        success(f"Saved {len(subdomains)} subdomains to {out_file}")
        print_module_summary(
            "Subdomain Summary",
            {
                "Target": domain,
                "Duration": f"{time.perf_counter() - started:.2f}s",
                "Sources Queried": len([status for status in source_status.values() if status not in {"Disabled"} and not status.startswith("Skipped")]),
                "Sources With Results": len({row["source"] for row in source_rows if row["source"] != "wordlist"}),
                "Sources Skipped": len([status for status in source_status.values() if status.startswith("Skipped") or status == "Disabled"]),
                "Passive Results": passive_results_count,
                "Wordlist Results": wordlist_results_count,
                "Filtered Results": wildcard_filtered_count,
                "Wildcard DNS": "Yes" if wildcard_detected else "No",
                "Final Results": len(subdomains),
                "Results Found": len(subdomains),
                "Output Location": out_dir,
            },
        )
    else:
        log.warning("No subdomains discovered")
        warn("No subdomains discovered")
        print_module_summary(
            "Subdomain Summary",
            {
                "Target": domain,
                "Duration": f"{time.perf_counter() - started:.2f}s",
                "Sources Queried": len([status for status in source_status.values() if status not in {"Disabled"} and not status.startswith("Skipped")]),
                "Sources With Results": 0,
                "Sources Skipped": len([status for status in source_status.values() if status.startswith("Skipped") or status == "Disabled"]),
                "Passive Results": passive_results_count,
                "Wordlist Results": wordlist_results_count,
                "Filtered Results": wildcard_filtered_count,
                "Wildcard DNS": "Yes" if wildcard_detected else "No",
                "Final Results": 0,
                "Results Found": 0,
                "Output Location": out_dir,
            },
        )


if __name__ == "__main__":
    run("example.com", Path("results"), passive=True, active=False)
