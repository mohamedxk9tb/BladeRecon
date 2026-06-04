"""Playwright-based screenshots module for BladeRecon.

Features:
- Asynchronous Playwright Chromium screenshots
- Accepts a single domain or a file with list of URLs/subdomains
- Configurable concurrency (default 10)
- Option for full page screenshots
- Saves PNGs to `output/<target>/screenshots/` with readable filenames
- Low-noise progress and error handling
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from rich.console import Console

from .utils import AsyncRateLimiter, ModuleResult, ProgressReporter, check_playwright_chromium, config_get, deduplicate_alive_urls, get_concurrency, get_profiled_ceiling, get_profiled_concurrency, get_profiled_per_host_concurrency, get_profiled_rate_limit, get_timeout, host_key, info, limit_items_with_notice, load_config, log_duration, normalize_scan_profile, normalize_target, prepare_module_output, print_module_summary, setup_logging, skipped_result, skip, success, target_output_dir, warn, write_json

console = Console()


@dataclass
class ScreenshotRunStats:
    queued: int = 0
    captured: int = 0
    failed: int = 0
    skipped: int = 0
    failures: List[Tuple[str, str]] = field(default_factory=list)


def _normalize_filename(url: str) -> str:
    """Create a filesystem-friendly filename for a URL."""
    # remove scheme
    filename = re.sub(r"^https?://", "", url)
    filename = filename.replace("/", "_")
    filename = filename.replace("?", "_")
    filename = filename.replace("&", "_")
    filename = filename.replace("=", "_")
    filename = re.sub(r"[^A-Za-z0-9_\-\.]+", "", filename)
    if len(filename) > 200:
        filename = filename[:200]
    return filename or "screenshot"


def _classify_navigation_error(exc: Exception, stage: str) -> str:
    """Return a concise operator-facing reason for a screenshot failure."""
    message = str(exc)
    lower = message.lower()
    if "timeout" in lower:
        return f"Navigation timeout during {stage}"
    if "cloudflare" in lower or "just a moment" in lower or "challenge" in lower:
        return "Cloudflare challenge"
    if "page closed" in lower or "target page, context or browser has been closed" in lower:
        return "Page closed"
    if "name_not_resolved" in lower or "dns" in lower or "err_name" in lower:
        return "DNS failure"
    if "ssl" in lower or "cert" in lower or "err_cert" in lower:
        return "SSL error"
    if "too many redirects" in lower or "redirect loop" in lower or "err_too_many_redirects" in lower:
        return "Redirect loop"
    if "err_connection" in lower or "connection refused" in lower or "connection reset" in lower:
        return "Connection failure"
    if "http " in lower:
        return message.splitlines()[0][:80]
    return f"{stage}: {message.splitlines()[0][:160]}"


async def _screenshot_page(page: Any, url: str, path: Path, full_page: bool, timeout: int = 45000) -> None:
    """Navigate to `url` and save a screenshot to `path`.

    Handles navigation timeouts and other network errors gracefully.
    """
    stage = "domcontentloaded"
    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        stage = "page inspection"
        try:
            title = (await page.title()).lower()
            if "just a moment" in title or "cloudflare" in title:
                raise RuntimeError("Cloudflare challenge detected")
        except RuntimeError:
            raise
        except Exception:
            pass
        if response is not None and getattr(response, "status", 0) >= 500:
            raise RuntimeError(f"HTTP {response.status}")
        stage = "screenshot capture"
        await page.screenshot(path=str(path), full_page=full_page)
    except Exception as exc:
        raise RuntimeError(f"{_classify_navigation_error(exc, stage)}: {url}") from exc


async def _worker(
    browser: Any,
    queue: asyncio.Queue,
    dest: Path,
    full_page: bool,
    timeout: int,
    captured: List[str],
    failed: List[Tuple[str, str]],
    reporter: Optional[ProgressReporter] = None,
    limiter: Optional[AsyncRateLimiter] = None,
    host_sems: Optional[Dict[str, asyncio.Semaphore]] = None,
    per_host_limit: int = 1,
) -> None:
    while True:
        url = await queue.get()
        if url is None:
            queue.task_done()
            return

        filename = _normalize_filename(url) + ".png"
        out_path = dest / filename
        try:
            last_error: Optional[Exception] = None
            for _ in range(2):
                page = None
                try:
                    if host_sems is None:
                        host_sems = {}
                    host_sem = host_sems.setdefault(host_key(url), asyncio.Semaphore(per_host_limit))
                    async with host_sem:
                        if limiter:
                            await limiter.wait()
                        page = await browser.new_page()
                        await _screenshot_page(page, url, out_path, full_page=full_page, timeout=timeout * 1000)
                    last_error = None
                    break
                except Exception as exc:
                    last_error = exc
                finally:
                    if page:
                        try:
                            await page.close()
                        except Exception:
                            pass
            if last_error:
                raise last_error
            captured.append(url)
        except Exception as exc:
            reason = str(exc).split(":", 1)[0].strip() or "Screenshot failed"
            failed.append((url, reason))
            console.log(f"[yellow]{exc}[/]")
        finally:
            if reporter:
                reporter.update(len(captured) + len(failed), detail=f"captured={len(captured)} failed={len(failed)}")
            queue.task_done()


async def _run_screenshots(urls: Iterable[str], dest: Path, concurrency: int = 10, full_page: bool = False, timeout: int = 45, profile: str = "balanced", config: Optional[dict] = None) -> ScreenshotRunStats:
    requested_urls = list(urls)
    urls = [
        url for url in urls
        if not ((dest / (_normalize_filename(url) + ".png")).exists() and (dest / (_normalize_filename(url) + ".png")).stat().st_size > 0)
    ]
    stats = ScreenshotRunStats(queued=len(urls), skipped=len(requested_urls) - len(urls))
    if not urls:
        return stats

    concurrency = max(1, min(concurrency, len(urls)))
    cfg = config or load_config()
    per_host_limit = get_profiled_per_host_concurrency("screenshots", 1, profile, cfg)
    limiter = AsyncRateLimiter(get_profiled_rate_limit("screenshots", 1, profile, cfg))
    host_sems: Dict[str, asyncio.Semaphore] = {}
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return ScreenshotRunStats(queued=len(urls), skipped=len(requested_urls), failures=[("", "Missing Playwright package")])

    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch(headless=True)
        except Exception as exc:
            raise RuntimeError(f"Playwright Chromium launch failed: {exc}") from exc

        dest.mkdir(parents=True, exist_ok=True)

        queue: asyncio.Queue = asyncio.Queue()
        captured: List[str] = []
        failed: List[Tuple[str, str]] = []
        reporter = ProgressReporter("Screenshots", total=len(urls), interval=10)
        reporter.update(0, detail=f"profile={profile} concurrency={concurrency} per_host={per_host_limit} rps={limiter.rate_per_second:g}", force=True)
        for url in urls:
            await queue.put(url)

        tasks = [
            asyncio.create_task(_worker(browser, queue, dest, full_page, timeout, captured, failed, reporter, limiter, host_sems, per_host_limit))
            for _ in range(concurrency)
        ]

        await queue.join()
        for _ in tasks:
            await queue.put(None)

        await asyncio.gather(*tasks, return_exceptions=True)
        reporter.update(len(urls), detail=f"captured={len(captured)} failed={len(failed)}", force=True)

        failed_file = dest / "failed_screenshots.txt"
        deduped_failures: Dict[str, str] = {}
        for url, reason in failed:
            deduped_failures.setdefault(url, reason)
        failed_file.write_text(
            "\n".join(f"{url}\t{reason}" for url, reason in deduped_failures.items() if url),
            encoding="utf-8",
        )
        stats.captured = len(captured)
        stats.failed = len(deduped_failures)
        stats.failures = list(deduped_failures.items())

        await browser.close()
    return stats


def _read_urls_from_file(path: Path) -> List[str]:
    lines = [l.strip() for l in path.read_text(encoding="utf-8").splitlines()]
    return [l for l in lines if l and not l.startswith("#")]


def _load_probe_rows(target_dir: Path) -> List[Dict[str, object]]:
    path = target_dir / "probe" / "probe.json"
    if not path.exists():
        path = target_dir / "probe" / "probe.jsonl"
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            data = json.loads(text)
            return data if isinstance(data, list) else []
        rows = []
        for line in text.splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows
    except Exception:
        return []


def _filter_screenshot_targets(urls: List[str], target_dir: Path, config: dict) -> List[str]:
    """Skip duplicate or low-value pages using lightweight probe metadata."""
    rows = _load_probe_rows(target_dir)
    if not rows:
        return urls

    wanted = set(urls)
    by_url = {str(row.get("final_url") or row.get("url")): row for row in rows}
    selected: List[str] = []
    seen_titles: Set[str] = set()
    seen_lengths: Set[int] = set()
    placeholders = [str(x).lower() for x in config_get(config, "screenshots.placeholder_titles", [])]
    skip_titles = bool(config_get(config, "screenshots.skip_duplicate_titles", True))
    skip_lengths = bool(config_get(config, "screenshots.skip_duplicate_content_lengths", True))

    for url in urls:
        row = by_url.get(url)
        if not row:
            selected.append(url)
            continue
        title = str(row.get("title") or "").strip().lower()
        length = int(row.get("content_length") or 0)
        status = int(row.get("status_code") or 0)
        if status in {301, 302, 303, 307, 308}:
            continue
        if title and any(token in title for token in placeholders):
            continue
        if skip_titles and title and title in seen_titles:
            continue
        if skip_lengths and length and length in seen_lengths:
            continue
        if title:
            seen_titles.add(title)
        if length:
            seen_lengths.add(length)
        selected.append(url)

    return [url for url in selected if url in wanted]


def run(domain: Optional[str] = None, list_file: Optional[Path] = None, output: Path = Path("results"), full_page: bool = False, concurrency: Optional[int] = None, resume: bool = False, profile: Optional[str] = None) -> ModuleResult:
    """Entry point for screenshotting.

    Provide either `domain` (a single target) or `list_file` (path to URLs).
    `output` is the base results directory.
    """
    if not domain and not list_file:
        warn("Either --domain or --list is required")
        return ModuleResult()

    urls: List[str] = []
    target_name = "screenshots"
    if list_file:
        if not list_file.exists():
            warn(f"List file not found: {list_file}")
            return ModuleResult()
        urls = _read_urls_from_file(list_file)
        target_name = normalize_target(list_file.stem)
    else:
        # assume domain; create common variants and canonical URL
        domain = domain.strip()
        target_name = normalize_target(domain)
        alive_file = target_output_dir(output, target_name) / "probe" / "alive.txt"
        if alive_file.exists():
            urls = _read_urls_from_file(alive_file)
        elif not domain.startswith("http"):
            urls = [f"https://{domain}", f"http://{domain}"]
        else:
            urls = [domain]

    dest = prepare_module_output(output, target_name, "screenshots", resume=resume)
    if not urls:
        warn("No URLs to screenshot")
        return skipped_result("No alive targets")
    urls = deduplicate_alive_urls(urls)
    log = setup_logging(target_name, output, "screenshots")
    started = time.perf_counter()
    config = load_config()
    active_profile = normalize_scan_profile(profile, config)
    timeout = get_timeout("screenshot", 45)
    concurrency = max(1, int(concurrency)) if concurrency is not None else get_profiled_concurrency("screenshots", get_concurrency("screenshots", 4), active_profile, config)
    before_filter = len(urls)
    urls = _filter_screenshot_targets(urls, target_output_dir(output, target_name), config)
    if not bool(config_get(config, "screenshots.browser_fallback_enabled", True)):
        skip("Screenshot module skipped")
        return skipped_result("Browser fallback disabled")
    max_browser_probes = max(0, int(config_get(config, "screenshots.max_browser_probes", 25)))
    profile_ceiling = get_profiled_ceiling("screenshots", max_browser_probes or 25, active_profile, config)
    if profile_ceiling:
        urls, profile_skipped = limit_items_with_notice(urls, profile_ceiling, "Screenshot requests")
    else:
        profile_skipped = 0
    if max_browser_probes and len(urls) > max_browser_probes:
        info(f"Limiting browser probes to {max_browser_probes} of {len(urls)} targets")
        urls = urls[:max_browser_probes]

    info(f"Screenshots queued: profile={active_profile} {len(urls)} targets ({before_filter - len(urls)} skipped) concurrency={concurrency}")

    chromium_ok, chromium_detail = check_playwright_chromium()
    if not chromium_ok:
        result = skipped_result(chromium_detail)
        skip("Screenshot module skipped")
        info(f"Reason: {result.reason}")
        summary = {
            "Target": target_name,
            "Duration": f"{time.perf_counter() - started:.2f}s",
            "Screenshots Status": "Skipped",
            "Reason": result.reason,
        }
        if "chromium browser not installed" in result.reason.lower():
            summary["Install Chromium"] = "python -m playwright install chromium"
        print_module_summary("Screenshot Summary", summary)
        log.warning("Screenshot module skipped: %s", result.reason)
        return result

    try:
        log.info("Starting screenshots for %d URLs", len(urls))
        with log_duration(log, "screenshots"):
            stats = asyncio.run(_run_screenshots(urls, dest, concurrency=concurrency, full_page=full_page, timeout=timeout, profile=active_profile, config=config))
        if stats.failures and stats.failures[0][1] == "Missing Playwright package":
            result = skipped_result("Missing Playwright package")
            skip("Screenshot module skipped")
            info(f"Reason: {result.reason}")
            summary = {
                "Target": target_name,
                "Duration": f"{time.perf_counter() - started:.2f}s",
                "Screenshots Status": "Skipped",
                "Reason": result.reason,
            }
            if "chromium browser not installed" in result.reason.lower():
                summary["Install Chromium"] = "python -m playwright install chromium"
            print_module_summary(
                "Screenshot Summary",
                summary,
            )
            log.warning("Screenshot module skipped: %s", result.reason)
            return result
        if stats.captured:
            success(f"Screenshots saved to {dest}")
        if stats.failed:
            warn(f"Screenshots failed for {stats.failed} target(s). See {dest / 'failed_screenshots.txt'}")
        write_json(
            dest / "metadata.json",
            {
                "safety_profile": active_profile,
                "queued": len(urls),
                "captured": stats.captured,
                "failed": stats.failed,
                "skipped": before_filter - len(urls) + stats.skipped,
                "concurrency": concurrency,
                "per_host_concurrency": get_profiled_per_host_concurrency("screenshots", 1, active_profile, config),
                "rate_limit_per_second": get_profiled_rate_limit("screenshots", 1, active_profile, config),
                "request_ceiling": profile_ceiling,
                "timeout": timeout,
            },
        )
        failure_reasons: Dict[str, int] = {}
        for _failed_url, reason in stats.failures:
            failure_reasons[reason] = failure_reasons.get(reason, 0) + 1
        summary = {
            "Target": target_name,
            "Duration": f"{time.perf_counter() - started:.2f}s",
            "Queued": len(urls),
            "Captured": stats.captured,
            "Failed": stats.failed,
            "Skipped": before_filter - len(urls) + stats.skipped,
            "Output Location": dest,
        }
        if failure_reasons:
            summary["Failure Reasons"] = ", ".join(f"{reason}={count}" for reason, count in sorted(failure_reasons.items()))
        print_module_summary(
            "Screenshot Summary",
            summary,
        )
        log.info("Screenshots saved to %s captured=%d failed=%d skipped=%d", dest, stats.captured, stats.failed, before_filter - len(urls) + stats.skipped)
        if stats.failures:
            for failed_url, reason in stats.failures:
                log.warning("Screenshot failed: %s (%s)", failed_url, reason)
        return ModuleResult(status="failed" if stats.failed and not stats.captured else "completed", reason=f"{stats.failed} screenshot(s) failed" if stats.failed else "")
    except Exception as exc:
        log.exception("Screenshots process failed")
        message = str(exc)
        warn(f"Screenshots process failed: {message}")
        return ModuleResult(status="failed", reason=message)

