"""Shared utilities for BladeRecon modules.

Provides configuration, CLI styling, logging, retry helpers, lightweight
state/cache handling, and output helpers used by the command modules.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import threading
import time
import tracemalloc
import inspect
import stat
import importlib.util
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple, TypeVar
from urllib.parse import urlsplit, urlunsplit

import yaml
from rich import box
from rich.console import Console
from rich.align import Align
from rich.text import Text
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

console = Console()

F = TypeVar("F", bound=Callable[..., Any])

PROJECT_NAME = "BladeRecon"
AUTHOR = "Mohamed Kotb"
GITHUB = "github.com/mohamedxk9tb"
BUILD_DATE = "2026-05-29"
CACHE_DIRNAME = ".cache"
HEALTH_OK = "OK"
HEALTH_WARN = "WARN"
HEALTH_MISSING = "MISSING"
HEALTH_FAILED = "FAILED"
REPORT_VERSION = "1"
SAFETY_PROFILES = {"safe", "balanced", "aggressive"}

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
]

DEFAULT_CONFIG: Dict[str, Any] = {
    "output_dir": "results",
    "scan_profile": "balanced",
    "dns_concurrency": 50,
    "dns_brute_prefixes": ["www", "web", "dev", "test", "staging", "mail", "admin", "ftp", "api", "vpn"],
    "wordlist_expansion": {
        "enabled": True,
        "threshold": 30,
        "concurrency": 30,
        "timeout": 3,
        "retries": 1,
    },
    "sources": {
        "crtsh": True,
        "alienvault": True,
        "chaos": True,
        "bufferover": True,
        "urlscan": True,
        "rapiddns": True,
        "anubis": False,
        "hackertarget": True,
    },
    "api_keys": {
        "alienvault": "",
        "chaos": "",
    },
    "timeouts": {
        "http": 10,
        "nuclei": 300,
        "screenshot": 45,
        "source": 30,
    },
    "concurrency": {
        "probe": 50,
        "js": 10,
        "screenshots": 4,
        "nuclei": 25,
        "dns": 50,
    },
    "retries": {
        "http": 1,
        "sources": 2,
        "screenshots": 1,
    },
    "rate_limits": {
        "probe": 12,
        "js": 6,
        "screenshots": 1,
        "nuclei": 25,
    },
    "request_ceilings": {
        "probe": 500,
        "js_html": 40,
        "js_downloads": 150,
        "screenshots": 25,
        "nuclei_targets": 250,
        "historical_urls": 1000,
        "content_discovery": 80,
        "security_header_hosts": 20,
        "historical_js": 40,
    },
    "per_host_concurrency": {
        "probe": 2,
        "js": 2,
        "screenshots": 1,
    },
    "backoff": {
        "base_delay": 0.5,
        "max_delay": 8.0,
        "status_codes": [429, 500, 502, 503, 504],
    },
    "safety_profiles": {
        "safe": {
            "concurrency": {"probe": 8, "js": 3, "screenshots": 1, "nuclei": 8, "dns": 20},
            "rate_limits": {"probe": 4, "js": 2, "screenshots": 0.5, "nuclei": 8},
            "request_ceilings": {"probe": 120, "js_html": 20, "js_downloads": 60, "screenshots": 10, "nuclei_targets": 80, "historical_urls": 300, "content_discovery": 30, "security_header_hosts": 8, "historical_js": 12},
            "per_host_concurrency": {"probe": 1, "js": 1, "screenshots": 1},
            "nuclei_profile": "safe",
        },
        "balanced": {
            "concurrency": {"probe": 50, "js": 10, "screenshots": 4, "nuclei": 25, "dns": 50},
            "rate_limits": {"probe": 12, "js": 6, "screenshots": 1, "nuclei": 25},
            "request_ceilings": {"probe": 500, "js_html": 40, "js_downloads": 150, "screenshots": 25, "nuclei_targets": 250, "historical_urls": 1000, "content_discovery": 80, "security_header_hosts": 20, "historical_js": 40},
            "per_host_concurrency": {"probe": 2, "js": 2, "screenshots": 1},
            "nuclei_profile": "balanced",
        },
        "aggressive": {
            "concurrency": {"probe": 100, "js": 20, "screenshots": 8, "nuclei": 50, "dns": 80},
            "rate_limits": {"probe": 30, "js": 15, "screenshots": 3, "nuclei": 50},
            "request_ceilings": {"probe": 1500, "js_html": 100, "js_downloads": 400, "screenshots": 75, "nuclei_targets": 750, "historical_urls": 3000, "content_discovery": 180, "security_header_hosts": 50, "historical_js": 100},
            "per_host_concurrency": {"probe": 4, "js": 3, "screenshots": 2},
            "nuclei_profile": "aggressive",
        },
    },
    "opsec": {
        "proxy": "",
        "http_proxy": "",
        "https_proxy": "",
        "socks5_proxy": "",
        "user_agent": "",
        "random_user_agent": False,
    },
    "screenshots": {
        "skip_duplicate_titles": True,
        "skip_duplicate_content_lengths": True,
        "placeholder_titles": ["parking", "coming soon", "default page", "welcome to nginx", "it works"],
        "browser_fallback_enabled": True,
        "max_browser_probes": 25,
    },
    "probe": {
        "browser_fallback_enabled": True,
        "max_browser_fallbacks": 10,
    },
    "js": {
        "max_html_pages": 40,
    },
    "nuclei_profiles": {
        "safe": {
            "severity": "critical,high,medium",
            "exclude_tags": "dos,bruteforce,intrusive,fuzz",
            "rate_limit": 10,
        },
        "balanced": {
            "severity": "critical,high,medium,low",
            "exclude_tags": "dos,bruteforce,intrusive",
            "rate_limit": 25,
        },
        "aggressive": {
            "severity": "critical,high,medium,low,info",
            "exclude_tags": "",
            "rate_limit": 50,
        },
    },
    "nuclei": {
        "automatic_scan": True,
        "count_templates_before_run": False,
        "request_timeout": 8,
        "retries": 0,
        "module_timeout": 0,
        "enforce_module_timeout": False,
        "progress_interval": 10,
        "baseline_scan": {
            "enabled": True,
            "severity": "critical,high",
            "max_targets": 50,
        },
    },
    "advanced": {
        "historical": {
            "max_urls": 1000,
            "sources": {
                "wayback": True,
                "commoncrawl": True,
                "alienvault": True,
            },
        },
        "content_discovery": {
            "max_hosts": 8,
            "max_requests": 80,
            "words": [],
        },
        "security_headers": {
            "max_hosts": 20,
        },
        "historical_js": {
            "max_files": 40,
        },
    },
}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _iter_config_paths(data: Dict[str, Any], prefix: Tuple[str, ...] = ()) -> Iterator[Tuple[Tuple[str, ...], Any]]:
    for key, value in data.items():
        path = (*prefix, str(key))
        yield path, value
        if isinstance(value, dict):
            yield from _iter_config_paths(value, path)


def _env_config_path(raw_key: str) -> Tuple[str, ...]:
    key = raw_key.lower()
    if "__" in key:
        return tuple(part for part in key.split("__") if part)
    known_paths = {
        "_".join(path): path
        for path, _value in _iter_config_paths(DEFAULT_CONFIG)
    }
    return known_paths.get(key, (key,))


def _coerce_env_value(value: str, current: Any = None) -> Any:
    raw = str(value).strip()
    if isinstance(current, bool):
        return raw.lower() in {"1", "true", "yes", "on"}
    if isinstance(current, int) and not isinstance(current, bool):
        try:
            return int(raw)
        except ValueError:
            return current
    if isinstance(current, float):
        try:
            return float(raw)
        except ValueError:
            return current
    if isinstance(current, list):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            pass
        return [item.strip() for item in raw.split(",") if item.strip()]
    if isinstance(current, dict):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else current
        except Exception:
            return current
    if raw.lower() in {"true", "false"}:
        return raw.lower() == "true"
    try:
        return json.loads(raw)
    except Exception:
        return value


def _deep_get(data: Dict[str, Any], path: Tuple[str, ...], default: Any = None) -> Any:
    current: Any = data
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _deep_set(data: Dict[str, Any], path: Tuple[str, ...], value: Any) -> None:
    current = data
    for part in path[:-1]:
        next_value = current.get(part)
        if not isinstance(next_value, dict):
            next_value = {}
            current[part] = next_value
        current = next_value
    current[path[-1]] = value


def load_config(path: Optional[Path] = None) -> dict:
    """Load project configuration and merge it with sane defaults."""
    cfg_path = path or Path("config.yaml")
    cfg: Dict[str, Any] = {}
    if cfg_path.exists():
        try:
            cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        except Exception:
            cfg = {}

    merged = _deep_merge(DEFAULT_CONFIG, cfg)
    for key, value in os.environ.items():
        if key.startswith("BLADERECON_"):
            config_path = _env_config_path(key[len("BLADERECON_"):])
            current_value = _deep_get(merged, config_path)
            _deep_set(merged, config_path, _coerce_env_value(value, current_value))
    return merged


def config_get(config: dict, dotted_key: str, default: Any = None) -> Any:
    """Return a nested config value using dot notation."""
    current: Any = config
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def normalize_scan_profile(profile: Optional[str], config: Optional[dict] = None) -> str:
    """Return a supported scan safety profile name."""
    cfg = config or load_config()
    value = str(profile or config_get(cfg, "scan_profile", "balanced") or "balanced").strip().lower()
    if value == "full":
        value = "aggressive"
    if value not in SAFETY_PROFILES:
        warn(f"Unknown scan profile '{value}', falling back to balanced")
        value = "balanced"
    return value


def safety_profile_settings(profile: Optional[str] = None, config: Optional[dict] = None) -> Dict[str, Any]:
    cfg = config or load_config()
    resolved = normalize_scan_profile(profile, cfg)
    profiles = config_get(cfg, "safety_profiles", {})
    selected = profiles.get(resolved, {}) if isinstance(profiles, dict) else {}
    return selected if isinstance(selected, dict) else {}


def profiled_config_get(config: dict, profile: Optional[str], dotted_key: str, default: Any = None) -> Any:
    selected = safety_profile_settings(profile, config)
    current: Any = selected
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return config_get(config, dotted_key, default)
        current = current[part]
    return current


def get_timeout(name: str, default: int = 10) -> int:
    """Get a timeout value from config.yaml or return *default* (seconds).

    Usage in config.yaml::

        timeouts:
          http: 10
          nuclei: 300
          screenshot: 20
    """
    cfg = load_config()
    return int(config_get(cfg, f"timeouts.{name}", default))


def get_concurrency(name: str, default: int) -> int:
    """Return configured module concurrency."""
    return max(1, int(config_get(load_config(), f"concurrency.{name}", default)))


def get_profiled_concurrency(name: str, default: int, profile: Optional[str] = None, config: Optional[dict] = None) -> int:
    cfg = config or load_config()
    return max(1, int(profiled_config_get(cfg, profile, f"concurrency.{name}", default)))


def get_profiled_rate_limit(name: str, default: float, profile: Optional[str] = None, config: Optional[dict] = None) -> float:
    cfg = config or load_config()
    return max(0.0, float(profiled_config_get(cfg, profile, f"rate_limits.{name}", default)))


def get_profiled_ceiling(name: str, default: int, profile: Optional[str] = None, config: Optional[dict] = None) -> int:
    cfg = config or load_config()
    return max(0, int(profiled_config_get(cfg, profile, f"request_ceilings.{name}", default)))


def get_profiled_per_host_concurrency(name: str, default: int, profile: Optional[str] = None, config: Optional[dict] = None) -> int:
    cfg = config or load_config()
    return max(1, int(profiled_config_get(cfg, profile, f"per_host_concurrency.{name}", default)))


def get_retries(name: str, default: int = 2) -> int:
    """Return configured retry count."""
    return max(0, int(config_get(load_config(), f"retries.{name}", default)))


# ---------------------------------------------------------------------------
# Deduplication / normalisation
# ---------------------------------------------------------------------------

def dedupe_preserve_order(values: Iterable[str]) -> List[str]:
    """Return non-empty unique strings while preserving first-seen order."""
    seen = set()
    deduped: List[str] = []
    for value in values:
        item = str(value).strip()
        if not item or item.startswith("#"):
            continue
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def normalize_url(url: str, strip_trailing_slash: bool = True) -> str:
    """Normalise a URL enough for safe deduplication without changing meaning."""
    value = url.strip()
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"

    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or ""
    if strip_trailing_slash and not parsed.query:
        path = path.rstrip("/")
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def deduplicate_subdomains(subdomains: Iterable[str]) -> List[str]:
    """Deduplicate subdomains with lowercase host normalisation."""
    cleaned = []
    for subdomain in subdomains:
        value = subdomain.strip().lower().rstrip(".")
        if value and "*" not in value and "/" not in value:
            cleaned.append(value)
    return dedupe_preserve_order(cleaned)


def deduplicate_alive_urls(urls: Iterable[str]) -> List[str]:
    """Deduplicate alive URLs, treating trailing slash-only variants as equal."""
    normalised = [normalize_url(url) for url in urls]
    return dedupe_preserve_order(u for u in normalised if u)


def deduplicate_parameters(parameters: Iterable[str]) -> List[str]:
    """Deduplicate parameter names while preserving original case and order."""
    seen = set()
    deduped: List[str] = []
    for parameter in parameters:
        value = parameter.strip()
        key = value.lower()
        if value and not value.startswith("#") and key not in seen:
            seen.add(key)
            deduped.append(value)
    return deduped


def deduplicate_prefixes(prefixes: Iterable[str]) -> List[str]:
    """Deduplicate DNS brute-force prefixes and ignore comments/empty lines."""
    cleaned = []
    for prefix in prefixes:
        value = prefix.strip().lower()
        if value and not value.startswith("#") and "." not in value:
            cleaned.append(value)
    return dedupe_preserve_order(cleaned)


def read_wordlist(path: Path) -> List[str]:
    """Read a wordlist, ignoring comments/empty lines and preserving order."""
    if not path.exists():
        return []
    return dedupe_preserve_order(path.read_text(encoding="utf-8").splitlines())


TRAVERSAL_PATTERN = re.compile(r"(^|[\\/])\.\.([\\/]|$)|\.\.[\\/]|[\\/]\.\.")
TARGET_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")


def normalize_target(value: str) -> str:
    """Normalize a CLI target into a safe results directory name."""
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("target cannot be empty")
    if "\x00" in raw or TRAVERSAL_PATTERN.search(raw):
        raise ValueError("target contains a path traversal sequence")
    if Path(raw).is_absolute():
        raise ValueError("target cannot be an absolute path")

    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    port = f"_{parsed.port}" if parsed.port else ""
    if not host:
        raise ValueError("target must include a hostname")
    if "/" in host or "\\" in host or host in {".", ".."} or ".." in host.split(os.sep):
        raise ValueError("target hostname is not safe")

    safe = f"{host}{port}"
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", safe).strip("._-")
    if not safe or not TARGET_NAME_PATTERN.match(safe):
        raise ValueError("target does not resolve to a safe results directory")
    return safe


def safe_target_name(value: str) -> str:
    """Return a filesystem-safe target folder name."""
    return normalize_target(value)


def ensure_within_directory(base: Path, candidate: Path) -> Path:
    """Resolve *candidate* and require it to stay inside *base*."""
    base_resolved = base.resolve()
    candidate_resolved = candidate.resolve()
    try:
        candidate_resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError(f"unsafe output path outside {base_resolved}") from exc
    return candidate_resolved


def target_output_dir(output: Path, target: str) -> Path:
    """Return the safe per-target output directory under *output*."""
    return ensure_within_directory(output, output / normalize_target(target))


def clear_module_output(output: Path, target: str, module_name: str) -> None:
    """Remove one module's stale artifacts while preserving logs/state."""
    if module_name in {"logs", "scan_state"}:
        raise ValueError("refusing to clear protected scan metadata")
    base = output.resolve()
    target_dir = target_output_dir(output, target)
    module_dir = ensure_within_directory(base, target_dir / module_name)
    if module_dir.exists():
        remove_tree(module_dir)


def prepare_module_output(output: Path, target: str, module_name: str, resume: bool = False) -> Path:
    """Return a clean module output directory unless resume mode is active."""
    target_dir = target_output_dir(output, target)
    out_dir = ensure_within_directory(output, target_dir / module_name)
    if not resume and out_dir.exists():
        remove_tree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def remove_tree(path: Path) -> None:
    """Remove a directory tree with small Windows lock/read-only tolerance."""
    def _onerror(func: Callable[..., Any], item: str, _exc_info: object) -> None:
        try:
            Path(item).chmod(Path(item).stat().st_mode | stat.S_IWRITE)
        except Exception:
            pass
        func(item)

    last_error: Optional[Exception] = None
    for _ in range(3):
        try:
            shutil.rmtree(path, onerror=_onerror)
            return
        except FileNotFoundError:
            return
        except Exception as exc:
            last_error = exc
            time.sleep(0.15)
    if last_error:
        raise last_error


def now_iso() -> str:
    """Return a compact UTC timestamp."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# CLI styling
# ---------------------------------------------------------------------------

def status(kind: str, message: str) -> None:
    """Print a consistent status line."""
    styles = {
        "INFO": "cyan",
        "SUCCESS": "green",
        "WARN": "yellow",
        "ERROR": "red",
        "SKIP": "yellow",
    }
    label = kind.upper()
    style = styles.get(label, "white")
    encoding = getattr(console.file, "encoding", None) or sys.stdout.encoding or "utf-8"
    safe_message = str(message).encode(encoding, errors="replace").decode(encoding, errors="replace")
    try:
        console.print(f"[{style}][{label}][/] {escape(safe_message)}")
    except OSError:
        fallback = getattr(sys, "__stdout__", None) or sys.stdout
        print(f"[{label}] {safe_message}", file=fallback)


def format_duration(seconds: float) -> str:
    """Return a compact HH:MM:SS duration for terminal status lines."""
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


class ProgressReporter:
    """Low-noise elapsed/counter printer for long-running CLI modules."""

    def __init__(self, name: str, total: Optional[int] = None, interval: float = 10.0) -> None:
        self.name = name
        self.total = total
        self.interval = max(1.0, float(interval))
        self.started = time.perf_counter()
        self.completed = 0
        self._last_emit = 0.0

    def update(self, completed: int, total: Optional[int] = None, detail: str = "", force: bool = False) -> None:
        self.completed = max(0, int(completed))
        if total is not None:
            self.total = total
        now = time.perf_counter()
        if not force and now - self._last_emit < self.interval:
            return
        self._last_emit = now
        elapsed = now - self.started
        progress_text = f"{self.completed}/{self.total}" if self.total else str(self.completed)
        suffix = f" | {detail}" if detail else ""
        info(f"{self.name}: {progress_text} elapsed={format_duration(elapsed)}{suffix}")

    def heartbeat(self, detail: str = "") -> None:
        self.update(self.completed, detail=detail)


class AsyncRateLimiter:
    """Small async token-spacer for module-level request pacing."""

    def __init__(self, rate_per_second: float) -> None:
        self.rate_per_second = max(0.0, float(rate_per_second))
        self._lock = asyncio.Lock()
        self._next_at = 0.0

    async def wait(self) -> None:
        if self.rate_per_second <= 0:
            return
        async with self._lock:
            now = time.perf_counter()
            if self._next_at > now:
                await asyncio.sleep(self._next_at - now)
                now = time.perf_counter()
            self._next_at = now + (1.0 / self.rate_per_second)


def host_key(value: str) -> str:
    parsed = urlsplit(value if "://" in value else f"//{value}")
    return (parsed.hostname or value).lower().rstrip(".")


def limit_items_with_notice(items: List[Any], ceiling: int, label: str) -> Tuple[List[Any], int]:
    if ceiling > 0 and len(items) > ceiling:
        warn(f"{label} capped at {ceiling} of {len(items)} item(s) by active safety profile")
        return items[:ceiling], len(items) - ceiling
    return items, 0


def info(message: str) -> None:
    status("INFO", message)


def success(message: str) -> None:
    status("SUCCESS", message)


def skip(message: str) -> None:
    status("SKIP", message)


def warn(message: str) -> None:
    status("WARN", message)


def error(message: str) -> None:
    status("ERROR", message)


@dataclass(frozen=True)
class ModuleResult:
    status: str = "completed"
    reason: str = ""


def skipped_result(reason: str) -> ModuleResult:
    return ModuleResult(status="skipped", reason=reason)


def check_playwright_chromium() -> Tuple[bool, str]:
    """Validate that Playwright Chromium is installed and launchable."""
    if importlib.util.find_spec("playwright") is None:
        return False, "Playwright package not importable"

    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception as exc:
        return False, f"Playwright import failed: {exc}"

    try:
        with sync_playwright() as pw:
            executable = Path(pw.chromium.executable_path)
            if not executable.exists():
                return False, "Chromium browser not installed"
            browser = pw.chromium.launch(headless=True)
            browser.close()
            return True, str(executable)
    except Exception as exc:
        message = str(exc)
        if "Executable doesn't exist" in message or "playwright install" in message:
            return False, "Chromium browser not installed"
        return False, f"Browser launch failed: {message[:160]}"


@dataclass
class DependencyHealth:
    name: str
    status: str
    reason: str
    version: str = ""
    details: str = ""

    @property
    def ok(self) -> bool:
        return self.status == HEALTH_OK

    def as_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "status": self.status,
            "reason": self.reason,
            "version": self.version,
            "details": self.details,
        }


def _version_command(executable: str, args: List[str], timeout: int = 15) -> Tuple[str, str]:
    try:
        proc = subprocess.run(
            [executable, *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except Exception as exc:
        return HEALTH_FAILED, str(exc)
    output = (proc.stdout or proc.stderr or "").strip()
    output = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output)
    if proc.returncode != 0:
        return HEALTH_FAILED, output or f"exit code {proc.returncode}"
    return HEALTH_OK, output.splitlines()[0] if output else "detected"


def _playwright_health() -> DependencyHealth:
    if importlib.util.find_spec("playwright") is None:
        return DependencyHealth("Playwright", HEALTH_MISSING, "Python package not importable")
    try:
        import playwright  # type: ignore

        return DependencyHealth("Playwright", HEALTH_OK, "Python package importable", details=str(Path(playwright.__file__).parent))
    except Exception as exc:
        return DependencyHealth("Playwright", HEALTH_FAILED, f"Import failed: {exc}")


def dependency_health(output: Path = Path("results"), template_dir: Optional[Path] = None) -> List[DependencyHealth]:
    """Return centralized runtime dependency health for doctor/readiness checks."""
    checks: List[DependencyHealth] = [
        DependencyHealth("Python", HEALTH_OK, "Runtime available", version=sys.version.split()[0], details=sys.executable),
    ]

    for name, executable, version_args in (
        ("Go", "go", ["version"]),
        ("Git", "git", ["--version"]),
        ("Nuclei Binary", "nuclei", ["-version", "-nc"]),
    ):
        found = shutil.which(executable)
        if not found:
            checks.append(DependencyHealth(name, HEALTH_MISSING, f"{executable} not found on PATH"))
            continue
        status_value, version = _version_command(found, version_args)
        checks.append(
            DependencyHealth(
                name,
                status_value,
                "Detected on PATH" if status_value == HEALTH_OK else "Version command failed",
                version=version,
                details=found,
            )
        )

    templates = nuclei_template_status(template_dir)
    if templates["ok"]:
        template_reason = "Templates detected"
        template_details = f"{templates['path']} | Source: {templates['source']} | Categories: {', '.join(templates['categories'])}"
    elif templates["status"] == HEALTH_WARN:
        template_reason = f"Directory appears incomplete: {', '.join(templates['missing']) or 'unknown'}"
        template_details = str(templates["path"])
    else:
        template_reason = f"Missing: {', '.join(templates['missing']) or 'unknown'}"
        template_details = str(templates["path"])
    checks.append(
        DependencyHealth(
            "Nuclei Templates",
            str(templates["status"]),
            template_reason,
            version=f"{templates['template_count']} templates" if templates["template_count"] else "",
            details=template_details,
        )
    )

    checks.append(_playwright_health())
    chromium_ok, chromium_detail = check_playwright_chromium()
    chromium_status = HEALTH_OK if chromium_ok else (HEALTH_MISSING if "not installed" in chromium_detail.lower() else HEALTH_FAILED)
    checks.append(DependencyHealth("Chromium", chromium_status, chromium_detail, details="Launch Test: Passed" if chromium_ok else "Launch Test: Failed"))

    try:
        output.mkdir(parents=True, exist_ok=True)
        checks.append(DependencyHealth("Output Directories", HEALTH_OK, "Output directory available", details=str(output)))
    except Exception as exc:
        checks.append(DependencyHealth("Output Directories", HEALTH_FAILED, str(exc), details=str(output)))

    try:
        output.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output, prefix=".doctor-", suffix=".tmp", delete=False) as handle:
            handle.write("ok")
            test_path = Path(handle.name)
        test_path.unlink(missing_ok=True)
        checks.append(DependencyHealth("Permissions", HEALTH_OK, "Can write to output directory", details=str(output)))
    except Exception as exc:
        checks.append(DependencyHealth("Permissions", HEALTH_FAILED, str(exc), details=str(output)))

    return checks


def readiness_failures(requirements: Iterable[str], output: Path = Path("results"), template_dir: Optional[Path] = None) -> List[DependencyHealth]:
    """Return failed health checks for the named requirements."""
    wanted = {name.lower() for name in requirements}
    return [check for check in dependency_health(output=output, template_dir=template_dir) if check.name.lower() in wanted and check.status != HEALTH_OK]


def suppress_third_party_banner(text: str, tool: str = "") -> str:
    """Remove third-party splash/banner text while preserving diagnostics."""
    tool_name = str(tool or "").strip().lower()
    filtered: List[str] = []
    for raw_line in str(text or "").splitlines():
        line = raw_line.rstrip()
        lower = line.lower()
        compact = re.sub(r"[\s_\\/|()[\]{}<>.-]+", "", lower)
        is_banner = False

        if tool_name == "nuclei":
            is_banner = (
                "projectdiscovery" in lower
                or "current nuclei version" in lower
                or "nuclei-templates version" in lower
                or "new templates added" in lower
                or "templates added in last update" in lower
                or "use with caution" in lower
                or compact in {"nuclei", "nucleiv"}
            )

        if tool_name == "subfinder":
            is_banner = (
                "projectdiscovery" in lower
                or "current subfinder version" in lower
                or compact in {"subfinder", "subfinderv"}
            )

        if not is_banner:
            filtered.append(line)
    return "\n".join(filtered).strip()


NUCLEI_TEMPLATE_CATEGORIES = {"cloud", "dns", "http", "network", "ssl", "workflows"}


def nuclei_template_status(template_dir: Optional[Path] = None, require_checksum: bool = True) -> Dict[str, Any]:
    """Return Nuclei template store status without invoking nuclei."""
    config_path = Path(os.environ.get("APPDATA", "")) / "nuclei" / ".templates-config.json"
    configured_dir = ""
    if config_path.exists():
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            configured_dir = str(data.get("nuclei-templates-directory") or "")
        except Exception:
            configured_dir = ""

    resolved_dir = Path(template_dir or configured_dir or (Path.home() / "nuclei-templates")).expanduser()
    if resolved_dir.is_file():
        has_templates = resolved_dir.suffix.lower() in {".yaml", ".yml"}
        checksum_exists = False
        git_exists = False
        is_empty = False
        has_categories = has_templates
        categories = []
        template_count = 1 if has_templates else 0
    else:
        has_templates = False
        template_count = 0
        categories = []
        is_empty = True
        try:
            if resolved_dir.exists():
                is_empty = not any(resolved_dir.iterdir())
                categories = sorted(
                    item.name
                    for item in resolved_dir.iterdir()
                    if item.is_dir() and item.name in NUCLEI_TEMPLATE_CATEGORIES
                )
            for item in resolved_dir.rglob("*"):
                if item.suffix.lower() in {".yaml", ".yml"}:
                    template_count += 1
                    has_templates = True
        except Exception:
            has_templates = False
        checksum_exists = (resolved_dir / ".checksum").exists()
        git_exists = (resolved_dir / ".git").exists()

    exists = resolved_dir.exists()
    if not resolved_dir.is_file():
        has_categories = bool(categories)
    categories_required = bool(require_checksum)
    ok = bool(exists and has_templates and (has_categories or not categories_required))
    if ok:
        status = "OK"
    elif exists and is_empty:
        status = "MISSING"
    elif not exists or (not has_templates and (not has_categories and categories_required)):
        status = "MISSING"
    else:
        status = "WARN"

    source = "Git Repository" if git_exists else "Nuclei Updater" if checksum_exists else "Detected"
    missing = []
    if not exists:
        missing.append("directory")
    if not has_templates:
        missing.append("templates")
    if categories_required and not has_categories:
        missing.append("categories")
    return {
        "ok": ok,
        "status": status,
        "path": str(resolved_dir),
        "configured_path": configured_dir,
        "exists": exists,
        "checksum_exists": checksum_exists,
        "git_exists": git_exists,
        "source": source,
        "categories": categories,
        "template_count": template_count,
        "missing": missing,
    }


def ui_box() -> box.Box:
    """Return a terminal-safe border style."""
    encoding = (getattr(console.file, "encoding", None) or sys.stdout.encoding or "utf-8").lower()
    return box.ROUNDED if "utf" in encoding else box.ASCII


def _safe_text(value: Any) -> str:
    encoding = getattr(console.file, "encoding", None) or sys.stdout.encoding or "utf-8"
    return str(value).encode(encoding, errors="replace").decode(encoding, errors="replace")


def _encoding_supports(text: str) -> bool:
    encoding = getattr(console.file, "encoding", None) or sys.stdout.encoding or "utf-8"
    try:
        text.encode(encoding)
        return True
    except UnicodeEncodeError:
        return False


def _banner_separator() -> str:
    return " | "


def _banner_body(version: str) -> Text:
    separator = _banner_separator()
    icon = "𖣘" if _encoding_supports("𖣘") else "*"
    body = Text(justify="center")
    body.append(f" {icon} ", style="dim deep_sky_blue1")
    body.append(" BladeRecon\n", style="bold bright_cyan")
    body.append("Precision Reconnaissance Framework\n", style="white")
    body.append(f"Surface Discovery{separator}Asset Intelligence{separator}Attack Mapping\n", style="cyan")
    body.append(f"Version {version}{separator}{AUTHOR}", style="dim white")
    return body


def banner_renderable(version: str, width: Optional[int] = None) -> Panel:
    """Return the compact BladeRecon startup header."""
    panel_width = min(width or console.width, 62)
    panel_width = max(panel_width, 44)
    return Panel(
        Align.center(_banner_body(version)),
        width=panel_width,
        border_style="steel_blue1",
        box=ui_box(),
        padding=(0, 1),
    )


def print_banner(version: str) -> None:
    """Render the BladeRecon startup banner."""
    try:
        console.print(banner_renderable(version), end="")
    except UnicodeEncodeError:
        fallback = Console(file=console.file, force_terminal=False, color_system=None, legacy_windows=True)
        fallback.print(banner_renderable(version), end="")


def print_module_header(title: str, target: Optional[str] = None) -> None:
    """Print a compact module start panel."""
    body = Text(justify="center")
    body.append(title, style="bold cyan")
    if target:
        body.append(f"\nTarget: {_safe_text(target)}", style="white")
    console.print(
        Panel(
            Align.center(body),
            width=42,
            border_style="steel_blue1",
            box=ui_box(),
            padding=(0, 1),
        )
    )


def print_scan_summary(summary: Dict[str, Any]) -> None:
    """Print a professional final scan summary table."""
    table = Table(title="Results", border_style="steel_blue1", show_header=True, box=ui_box())
    table.add_column("Metric", style="white")
    table.add_column("Value", style="cyan")
    for key in (
        "Target",
        "Duration",
        "Subdomains Found",
        "Alive Hosts",
        "JavaScript Files",
        "Endpoints Found",
        "Secrets Detected",
        "Parameters Found",
        "Screenshots Captured",
        "Nuclei Findings",
        "Risk Score",
        "Output Location",
    ):
        table.add_row(key, str(summary.get(key, "Not Run")))
    console.print(Panel(table, title="BladeRecon Scan Summary", border_style="steel_blue1", box=ui_box(), padding=(0, 1)))


def print_module_summary(title: str, rows: Dict[str, Any]) -> None:
    """Print a compact command/module completion summary."""
    table = Table(border_style="steel_blue1", show_header=False, box=ui_box())
    table.add_column("Metric", style="white")
    table.add_column("Value", style="cyan")
    for key, value in rows.items():
        table.add_row(_safe_text(key), _safe_text(value))
    console.print(Panel(table, title=title, border_style="steel_blue1", box=ui_box(), padding=(0, 1)))


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(domain: str, output: Path, module_name: str) -> logging.Logger:
    """Initialise file and console logging for *module_name*.

    Creates ``results/<domain>/logs/scan.log`` and ``errors.log`` on first
    call.  Subsequent calls for the same domain attach to the existing root
    logger and just add a module-specific prefix.
    """
    safe_domain = normalize_target(domain)
    log_dir = target_output_dir(output, safe_domain) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(f"bladerecon.{safe_domain}.{module_name}")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    scan_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    err_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s\n%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    handler_paths = {
        str(getattr(handler, "baseFilename", ""))
        for handler in logger.handlers
        if isinstance(handler, logging.FileHandler)
    }

    scan_path = str((log_dir / "scan.log").resolve())
    if scan_path not in handler_paths:
        scan_fh = logging.FileHandler(scan_path, encoding="utf-8")
        scan_fh.setLevel(logging.INFO)
        scan_fh.setFormatter(scan_fmt)
        logger.addHandler(scan_fh)

    err_path = str((log_dir / "errors.log").resolve())
    if err_path not in handler_paths:
        err_fh = logging.FileHandler(err_path, encoding="utf-8")
        err_fh.setLevel(logging.ERROR)
        err_fh.setFormatter(err_fmt)
        logger.addHandler(err_fh)

    logger.info("Module started: %s", module_name)
    return logger


@contextmanager
def log_duration(logger: logging.Logger, label: str) -> Iterator[None]:
    """Log elapsed time for a module or scan step."""
    started = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - started
        logger.info("%s duration: %.2fs", label, elapsed)


def write_scan_metadata(domain: str, output: Path, **metadata: Any) -> None:
    """Persist lightweight scan metadata for reports."""
    log_dir = target_output_dir(output, domain) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    meta_path = log_dir / "scan_meta.json"
    existing: dict = {}
    if meta_path.exists():
        try:
            existing = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    existing.update({"updated_at": now_iso(), "report_version": REPORT_VERSION, **metadata})
    write_json(meta_path, existing)


def _process_metrics() -> Dict[str, float]:
    """Return current process CPU/RAM metrics with optional psutil support."""
    try:
        import psutil  # type: ignore

        proc = psutil.Process(os.getpid())
        ram = float(proc.memory_info().rss) / (1024 * 1024)
        return {"cpu_percent": 0.0, "ram_mb": ram}
    except Exception:
        pass
    if platform.system() == "Windows":
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                return {"cpu_percent": 0.0, "ram_mb": float(counters.WorkingSetSize) / (1024 * 1024)}
        except Exception:
            pass
    if tracemalloc.is_tracing():
        current, _peak = tracemalloc.get_traced_memory()
        return {"cpu_percent": 0.0, "ram_mb": float(current) / (1024 * 1024)}
    try:
        import resource  # type: ignore

        usage = resource.getrusage(resource.RUSAGE_SELF)
        peak = float(usage.ru_maxrss)
        if platform.system() != "Darwin":
            peak = peak / 1024
        return {"cpu_percent": 0.0, "ram_mb": peak}
    except Exception:
        return {"cpu_percent": 0.0, "ram_mb": 0.0}


class PerformanceMonitor:
    """Low-overhead process sampler for scan/report observability."""

    def __init__(self, interval: float = 0.5) -> None:
        self.interval = max(0.2, float(interval))
        self.started_at = now_iso()
        self.ended_at = ""
        self._samples: List[Dict[str, float]] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_wall = time.perf_counter()
        self._last_cpu = time.process_time()

    def start(self) -> "PerformanceMonitor":
        if not tracemalloc.is_tracing():
            tracemalloc.start()
        self._record_sample()
        self._thread = threading.Thread(target=self._run, name="bladerecon-perf", daemon=True)
        self._thread.start()
        return self

    def _record_sample(self) -> None:
        now_wall = time.perf_counter()
        now_cpu = time.process_time()
        elapsed = max(0.001, now_wall - self._last_wall)
        cpu_percent = max(0.0, ((now_cpu - self._last_cpu) / elapsed) * 100.0)
        metrics = _process_metrics()
        metrics["cpu_percent"] = round(cpu_percent, 2)
        self._samples.append(metrics)
        self._last_wall = now_wall
        self._last_cpu = now_cpu

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self._record_sample()

    def stop(self) -> Dict[str, Any]:
        self._record_sample()
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        self.ended_at = now_iso()
        return self.summary()

    def summary(self) -> Dict[str, Any]:
        samples = self._samples or [_process_metrics()]
        ram_values = [sample.get("ram_mb", 0.0) for sample in samples]
        cpu_values = [sample.get("cpu_percent", 0.0) for sample in samples]
        return {
            "scan_start_time": self.started_at,
            "scan_end_time": self.ended_at or now_iso(),
            "peak_ram_mb": round(max(ram_values, default=0.0), 2),
            "average_ram_mb": round(sum(ram_values) / max(1, len(ram_values)), 2),
            "peak_cpu_percent": round(max(cpu_values, default=0.0), 2),
            "average_cpu_percent": round(sum(cpu_values) / max(1, len(cpu_values)), 2),
            "sample_count": len(samples),
        }


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    """Write text to *path* via a same-directory temporary file and atomic replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding=encoding,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_path = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    finally:
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


def write_json(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    atomic_write_text(path, "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


# ---------------------------------------------------------------------------
# Scan state / cache
# ---------------------------------------------------------------------------

def scan_state_path(domain: str, output: Path) -> Path:
    return target_output_dir(output, domain) / "scan_state.json"


def load_scan_state(domain: str, output: Path) -> dict:
    path = scan_state_path(domain, output)
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _framework_version() -> str:
    try:
        from .. import __version__

        return str(__version__)
    except Exception:
        return "unknown"


def _ensure_scan_state_metadata(domain: str, state: dict) -> dict:
    state.setdefault("target", domain)
    state.setdefault("scan_id", uuid.uuid4().hex)
    state.setdefault("scan_profile", "standard")
    state.setdefault("framework_version", _framework_version())
    state.setdefault("report_version", REPORT_VERSION)
    state.setdefault("state_version", 1)
    return state


def save_scan_state(domain: str, output: Path, state: dict) -> None:
    path = scan_state_path(domain, output)
    path.parent.mkdir(parents=True, exist_ok=True)
    _ensure_scan_state_metadata(domain, state)
    state["updated_at"] = now_iso()
    write_json(path, state)


def update_scan_state(domain: str, output: Path, module: str, status_value: str, duration: float, error_text: str = "", performance: Optional[Dict[str, Any]] = None) -> None:
    state = load_scan_state(domain, output)
    modules = state.setdefault("modules", {})
    modules[module] = {
        "status": status_value,
        "duration_seconds": round(duration, 2),
        "updated_at": now_iso(),
        "error": error_text,
    }
    if performance:
        modules[module]["performance"] = performance
    completed = state.setdefault("completed_modules", [])
    failed = state.setdefault("failed_modules", [])
    skipped = state.setdefault("skipped_modules", [])
    if status_value == "completed":
        if module not in completed:
            completed.append(module)
        if module in failed:
            failed.remove(module)
        if module in skipped:
            skipped.remove(module)
    elif status_value in {"failed", "timed_out"}:
        if module not in failed:
            failed.append(module)
        if module in skipped:
            skipped.remove(module)
        if module in completed:
            completed.remove(module)
    elif status_value == "skipped":
        if module not in skipped:
            skipped.append(module)
        if module in failed:
            failed.remove(module)
        if module in completed:
            completed.remove(module)
    save_scan_state(domain, output, state)


def get_cache_root(output: Path) -> Path:
    return output / CACHE_DIRNAME


def cache_path(output: Path, source: str, domain: str) -> Path:
    return get_cache_root(output) / source / f"{safe_target_name(domain)}.json"


def load_cache(output: Path, source: str, domain: str, max_age_seconds: int = 86400) -> Optional[Any]:
    path = cache_path(output, source, domain)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        age = time.time() - float(payload.get("created_epoch", 0))
        if age > max_age_seconds:
            return None
        return payload.get("data")
    except Exception:
        return None


def save_cache(output: Path, source: str, domain: str, data: Any) -> None:
    path = cache_path(output, source, domain)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"source": source, "domain": domain, "created_at": now_iso(), "created_epoch": time.time(), "data": data}
    write_json(path, payload)


def cache_info(output: Path) -> dict:
    root = get_cache_root(output)
    files = list(root.rglob("*.json")) if root.exists() else []
    sizes = []
    mtimes = []
    for path in files:
        try:
            stat_result = path.stat()
            sizes.append(stat_result.st_size)
            mtimes.append(stat_result.st_mtime)
        except OSError:
            continue
    size = sum(sizes)
    sources = sorted({p.parent.name for p in files})
    newest = max(mtimes, default=0)
    oldest = min(mtimes, default=0)
    return {
        "path": str(root),
        "files": len(files),
        "size_bytes": size,
        "size_human": f"{size / 1024:.1f} KB",
        "sources": sources,
        "newest_age_seconds": int(time.time() - newest) if newest else None,
        "oldest_age_seconds": int(time.time() - oldest) if oldest else None,
    }


def _make_writable(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | stat.S_IWRITE)
    except Exception:
        pass


def clear_cache(output: Path) -> Tuple[int, int]:
    """Safely clear cache files.

    Returns ``(removed, skipped)`` and avoids raising on locked or read-only
    files so CLI users never see a traceback during cleanup.
    """
    root = get_cache_root(output)
    if not root.exists():
        return 0, 0

    removed = 0
    locked: Dict[Path, str] = {}

    for _ in range(3):
        progress = False
        locked.clear()
        for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            try:
                _make_writable(path)
                if path.is_dir():
                    path.rmdir()
                else:
                    path.unlink()
                removed += 1
                progress = True
            except FileNotFoundError:
                progress = True
            except PermissionError as exc:
                locked[path] = str(exc)
            except OSError as exc:
                locked[path] = str(exc)
        if not locked or not progress:
            break
        time.sleep(0.15)

    for path, message in locked.items():
        warn(f"Unable to remove locked cache file: {path}" + (f" ({message})" if message else ""))

    try:
        root.rmdir()
        removed += 1
    except FileNotFoundError:
        pass
    except OSError:
        pass

    return removed, len(locked)


# ---------------------------------------------------------------------------
# OPSEC / HTTP helpers
# ---------------------------------------------------------------------------

def pick_user_agent(config: Optional[dict] = None, user_agent: Optional[str] = None, random_user_agent: bool = False) -> str:
    cfg = config or load_config()
    configured = user_agent or str(config_get(cfg, "opsec.user_agent", "") or "")
    random_mode = random_user_agent or bool(config_get(cfg, "opsec.random_user_agent", False))
    if random_mode:
        return random.choice(DEFAULT_USER_AGENTS)
    return configured or DEFAULT_USER_AGENTS[0]


def build_headers(config: Optional[dict] = None, user_agent: Optional[str] = None, random_user_agent: bool = False) -> Dict[str, str]:
    return {"User-Agent": pick_user_agent(config, user_agent, random_user_agent)}


def get_proxy(config: Optional[dict] = None, proxy: Optional[str] = None) -> Optional[str]:
    cfg = config or load_config()
    return proxy or config_get(cfg, "opsec.proxy") or config_get(cfg, "opsec.https_proxy") or config_get(cfg, "opsec.http_proxy") or config_get(cfg, "opsec.socks5_proxy") or None


def httpx_client_kwargs(config: Optional[dict] = None, proxy: Optional[str] = None, user_agent: Optional[str] = None, random_user_agent: bool = False) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {"headers": build_headers(config, user_agent, random_user_agent)}
    resolved_proxy = get_proxy(config, proxy)
    if resolved_proxy:
        try:
            import httpx  # type: ignore

            if "proxy" in inspect.signature(httpx.AsyncClient).parameters:
                kwargs["proxy"] = resolved_proxy
            else:
                kwargs["proxies"] = resolved_proxy
        except Exception:
            kwargs["proxy"] = resolved_proxy
    return kwargs


def version_info(version: str) -> Dict[str, str]:
    return {
        "version": version,
        "build_date": BUILD_DATE,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }


# ---------------------------------------------------------------------------
# Retry decorator
# ---------------------------------------------------------------------------

def retry(
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
) -> Callable[[F], F]:
    """Retry a function with exponential backoff.

    Parameters
    ----------
    max_retries : int
        Maximum number of retry attempts (0 = no retries).
    delay : float
        Initial delay in seconds between retries.
    backoff : float
        Multiplier applied to *delay* after each failed attempt.
    exceptions : tuple
        Exception types that trigger a retry.
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            current_delay = delay
            last_exc: Optional[BaseException] = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt < max_retries:
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        raise
            raise last_exc  # type: ignore[misc]
        return wrapper  # type: ignore[return-value]
    return decorator


async def async_retry(
    func: Callable[..., Any],
    *args: Any,
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
    **kwargs: Any,
) -> Any:
    """Retry an async callable with exponential backoff."""
    current_delay = delay
    for attempt in range(max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except exceptions:
            if attempt >= max_retries:
                raise
            await asyncio.sleep(current_delay)
            current_delay *= backoff
