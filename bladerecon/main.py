"""BladeRecon main CLI entrypoint.

This module defines the CLI using Typer and implements the primary commands.
The implementation focuses on clean code, helpful messages, and a small but
working subdomain collector (crt.sh). Other modules are scaffolded to be
implemented under `bladerecon.modules`.
"""
from __future__ import annotations

import os
import json
import io
import time
import tempfile
import urllib.request
import zipfile
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import typer
import yaml
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typer.core import TyperGroup
import platform
import shutil
import subprocess
import sys

from . import __version__
from .modules.utils import (
    banner_renderable,
    cache_info as get_cache_info,
    check_playwright_chromium,
    clear_cache,
    dependency_health,
    error,
    format_duration,
    create_scan_run_output_dir,
    info,
    load_config as load_project_config,
    normalize_scan_profile,
    normalize_target,
    PerformanceMonitor,
    nuclei_template_status,
    print_module_header,
    print_module_summary,
    print_scan_summary,
    readiness_failures,
    scan_state_path,
    skip,
    resolve_latest_run_output_dir,
    save_scan_state,
    success,
    target_output_dir,
    update_scan_state,
    version_info,
    ui_box,
    warn,
    write_scan_metadata,
)


COMMAND_GROUPS = {
    "Recon": [
        ("scan", "Start a standard full workflow (alias for full)"),
        ("subdomain", "Discover subdomains from multiple sources"),
        ("probe", "Probe alive hosts"),
        ("js", "Discover JavaScript assets"),
        ("endpoints", "Extract endpoints from JavaScript"),
        ("secrets", "Detect exposed JavaScript secrets"),
        ("param", "Discover URL parameters"),
        ("intelligence", "Generate recon intelligence"),
        ("full", "Run full workflow"),
    ],
    "Analysis": [
        ("screenshot", "Capture web screenshots"),
        ("nuclei", "Scan with Nuclei templates"),
        ("advanced", "Generate advanced recon intelligence"),
        ("report", "Generate reports"),
    ],
    "Utilities": [
        ("doctor", "Check runtime readiness"),
        ("repair", "Repair recoverable dependencies"),
        ("cache", "Manage passive-source cache"),
        ("resume", "Resume saved scan state"),
        ("install-deps", "Install external tooling"),
    ],
}

NUCLEI_INSTALL_TARGET = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
NUCLEI_LATEST_RELEASE_API = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
BANNER_DISABLED = False


def _should_hide_banner() -> bool:
    return BANNER_DISABLED or "--no-banner" in sys.argv[1:]


def _terminal_safe(text: str) -> str:
    """Return text printable by the current stdout encoding."""
    encoding = sys.stdout.encoding or "utf-8"
    return text.encode(encoding, errors="replace").decode(encoding, errors="replace")


def _render_root_help(no_banner: bool = False) -> str:
    """Render the custom root help screen for all root entry paths."""
    help_console = Console(
        width=console.width,
        file=io.StringIO(),
        record=True,
        force_terminal=console.is_terminal,
        color_system=console.color_system,
        legacy_windows=console.legacy_windows,
    )
    border = ui_box()
    if not no_banner:
        help_console.print(banner_renderable(__version__), end="")
        help_console.print()
    help_console.print("[white]Usage:[/] [cyan]bladerecon[/] [white][OPTIONS] COMMAND [ARGS]...[/]")
    help_console.print("[dim]Lightweight reconnaissance for attack-surface discovery.[/]")
    help_console.print()
    help_console.print("[cyan]Start Here[/]")
    help_console.print("  [white]bladerecon doctor[/]")
    help_console.print("  [white]bladerecon full example.com --profile safe[/]")
    help_console.print("  [white]bladerecon report example.com[/]")
    help_console.print("[dim]Tip: `bladerecon scan` is an alias for `bladerecon full`.[/]")
    help_console.print()

    for group_name, commands in COMMAND_GROUPS.items():
        help_console.print(f"[cyan]{group_name}[/]")
        table = Table(
            border_style="steel_blue1",
            box=border,
            show_header=True,
            header_style="cyan",
            padding=(0, 1),
        )
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Description", style="white", no_wrap=True)
        for command, description in commands:
            table.add_row(command, description)
        help_console.print(table)
        help_console.print()

    help_console.print("[white]Options:[/]")
    help_console.print("  [cyan]--version[/]   Show BladeRecon version and exit")
    help_console.print("  [cyan]--help[/]      Show this help screen and exit")
    help_console.print()
    command_count = sum(len(items) for items in COMMAND_GROUPS.values())
    help_console.print(f"[dim]Python {sys.version.split()[0]} | {command_count} Commands[/]")

    return _terminal_safe(help_console.export_text(styles=help_console.is_terminal))


class BladeReconGroup(TyperGroup):
    """Custom root help renderer for BladeRecon's first screen."""

    def format_help(self, ctx: typer.Context, formatter: object) -> None:  # type: ignore[override]
        formatter.write(_render_root_help(no_banner=_should_hide_banner()))  # type: ignore[attr-defined]


app = typer.Typer(
    help="BladeRecon - Fast, lightweight reconnaissance framework for attack surface discovery, bug bounty hunting, and web security.",
    cls=BladeReconGroup,
    rich_markup_mode="rich",
    no_args_is_help=False,
)
cache_app = typer.Typer(help="Manage BladeRecon passive-source cache.", no_args_is_help=True)
app.add_typer(cache_app, name="cache")
console = Console()


def load_config(path: Optional[Path]) -> dict:
    """Load configuration from YAML file and environment variables.

    Environment variables prefixed with `BLADERECON_` override YAML values.
    """
    return load_project_config(path)


@app.callback(invoke_without_command=True)
def cli(
    ctx: typer.Context,
    version_flag: bool = typer.Option(False, "--version", help="Show BladeRecon version and exit."),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress BladeRecon banner output.", hidden=True),
) -> None:
    """BladeRecon command line interface."""
    global BANNER_DISABLED
    BANNER_DISABLED = no_banner
    if version_flag:
        version()
        raise typer.Exit()
    if any(arg in {"--help", "-h"} for arg in sys.argv[1:]):
        return
    if ctx.invoked_subcommand is None:
        sys.stdout.write(_render_root_help(no_banner=no_banner))
        raise typer.Exit()


def ensure_output_dir(path: Path) -> Path:
    """Create and return the output directory path (ensures parent exists)."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def _deprecated_domain(command: str, domain: Optional[str], domain_option: Optional[str]) -> Optional[str]:
    """Resolve hidden -d/--domain compatibility aliases for target commands."""
    if domain_option:
        warn(f"--domain is deprecated. Use: bladerecon {command} {domain_option}")
        return domain_option
    return domain


def _require_domain(command: str, domain: Optional[str], domain_option: Optional[str] = None) -> str:
    resolved = _deprecated_domain(command, domain, domain_option)
    if not resolved:
        error(f"Please provide a target domain. Usage: bladerecon {command} example.com")
        raise typer.Exit(code=1)
    try:
        return normalize_target(resolved)
    except ValueError as exc:
        error(f"Invalid target: {exc}")
        raise typer.Exit(code=1) from exc


def _normalize_optional_target(command: str, domain: Optional[str], domain_option: Optional[str] = None) -> Optional[str]:
    resolved = _deprecated_domain(command, domain, domain_option)
    if not resolved:
        return None
    try:
        return normalize_target(resolved)
    except ValueError as exc:
        error(f"Invalid target: {exc}")
        raise typer.Exit(code=1) from exc


def _get_go_bin_path() -> Optional[Path]:
    """Return the Go bin directory if Go is installed."""
    go_exec = shutil.which("go")
    if not go_exec:
        return None

    try:
        gobin_proc = subprocess.run([go_exec, "env", "GOBIN"], capture_output=True, text=True, check=False)
        gobin = gobin_proc.stdout.strip()
        if gobin:
            return Path(gobin).expanduser()

        gopath_proc = subprocess.run([go_exec, "env", "GOPATH"], capture_output=True, text=True, check=False)
        gopath = gopath_proc.stdout.strip()
        if gopath:
            return Path(gopath).expanduser() / "bin"
    except Exception:
        return None

    return None


def _default_windows_bin_dir() -> Path:
    return Path(os.environ.get("USERPROFILE") or str(Path.home())) / "go" / "bin"


def _collect_traffic_counts(domain: str, output: Path) -> Dict[str, int]:
    target_dir = target_output_dir(output, domain)
    probe_path = target_dir / "probe" / "probe.json"
    rows: List[dict] = []
    if probe_path.exists():
        try:
            data = json.loads(probe_path.read_text(encoding="utf-8-sig"))
            rows = data if isinstance(data, list) else []
        except Exception:
            rows = []
    requests_sent = len(rows)
    responses_received = len([row for row in rows if isinstance(row, dict) and row.get("status_code")])
    for metadata_path in (
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
        if not isinstance(metadata, dict):
            continue
        if metadata_path.name == "advanced_metadata.json":
            requests_sent += int(metadata.get("requests_sent", 0) or 0)
        elif metadata_path.parent.name == "js":
            requests_sent += int(metadata.get("html_requests", 0) or 0)
            requests_sent += int(metadata.get("download_requests", 0) or 0)
        elif metadata_path.parent.name == "screenshots":
            requests_sent += int(metadata.get("queued", 0) or 0)
        elif metadata_path.parent.name == "nuclei":
            targets = int(metadata.get("targets_count", 0) or 0)
            templates = int(metadata.get("templates_executed", metadata.get("template_candidates", 0)) or 0)
            requests_sent += max(0, targets * templates)
            baseline = metadata.get("baseline_scan", {}) if isinstance(metadata.get("baseline_scan"), dict) else {}
            if baseline.get("applied"):
                baseline_targets = int(baseline.get("targets_count", 0) or 0)
                baseline_templates = int(baseline.get("templates_executed", baseline.get("template_candidates", 0)) or 0)
                requests_sent += max(0, baseline_targets * baseline_templates)
    return {"total_requests_sent": requests_sent, "total_responses_received": responses_received}


def _module_duration_rows(domain: str, output: Path) -> List[Tuple[str, float, str]]:
    state_file = target_output_dir(output, domain) / "scan_state.json"
    if not state_file.exists():
        return []
    try:
        state = json.loads(state_file.read_text(encoding="utf-8-sig"))
    except Exception:
        return []
    modules = state.get("modules", {}) if isinstance(state, dict) else {}
    rows: List[Tuple[str, float, str]] = []
    if not isinstance(modules, dict):
        return rows
    for name, data in modules.items():
        if not isinstance(data, dict):
            continue
        try:
            duration = float(data.get("duration_seconds") or 0)
        except (TypeError, ValueError):
            duration = 0
        if duration > 0:
            rows.append((str(name), duration, str(data.get("status") or "")))
    return rows


def _print_slowest_modules(domain: str, output: Path, limit: int = 4) -> None:
    rows = sorted(_module_duration_rows(domain, output), key=lambda item: item[1], reverse=True)[:limit]
    if not rows:
        return
    table = Table(title="Top Slowest Modules", box=box.SIMPLE_HEAVY)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Module", style="bold")
    table.add_column("Duration", justify="right")
    table.add_column("Status")
    for idx, (name, duration, status) in enumerate(rows, 1):
        table.add_row(str(idx), name, format_duration(duration), status.title() if status else "-")
    console.print(table)


def _path_entries(value: str) -> List[str]:
    return [item.strip().strip('"') for item in value.split(os.pathsep) if item.strip()]


def _path_contains(path_value: str, directory: Path) -> bool:
    target = str(directory.resolve()).lower()
    for entry in _path_entries(path_value):
        try:
            if str(Path(entry).resolve()).lower() == target:
                return True
        except Exception:
            if entry.lower() == str(directory).lower():
                return True
    return False


def _ensure_windows_user_path(directory: Path) -> bool:
    """Add *directory* to the current process and user PATH on Windows."""
    current_path = os.environ.get("PATH", "")
    if not _path_contains(current_path, directory):
        os.environ["PATH"] = current_path + os.pathsep + str(directory) if current_path else str(directory)

    try:
        import winreg  # type: ignore

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            try:
                user_path, _ = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                user_path = ""
            if _path_contains(str(user_path), directory):
                return False
            updated = str(user_path) + os.pathsep + str(directory) if user_path else str(directory)
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, updated)
        return True
    except Exception as exc:
        warn(f"Unable to update user PATH automatically: {exc}")
        return False


def _fetch_json(url: str, timeout: int = 60) -> Dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": f"BladeRecon/{__version__}"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _select_windows_nuclei_asset(release: Dict[str, Any]) -> Tuple[str, str]:
    assets = release.get("assets", [])
    if not isinstance(assets, list):
        raise RuntimeError("GitHub release response did not include assets")
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name") or "").lower()
        url = str(asset.get("browser_download_url") or "")
        if "windows" in name and "amd64" in name and name.endswith(".zip") and url:
            return str(asset.get("name") or "nuclei_windows_amd64.zip"), url
    raise RuntimeError("Unable to find Nuclei Windows AMD64 release asset")


def _download_file(url: str, destination: Path, timeout: int = 300) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": f"BladeRecon/{__version__}"})
    with urllib.request.urlopen(request, timeout=timeout) as response, destination.open("wb") as fh:
        total = int(response.headers.get("Content-Length") or 0)
        downloaded = 0
        last_report = time.monotonic()
        while True:
            chunk = response.read(1024 * 512)
            if not chunk:
                break
            fh.write(chunk)
            downloaded += len(chunk)
            now = time.monotonic()
            if now - last_report >= 5:
                if total:
                    info(f"Download progress: {downloaded / total:.0%}")
                else:
                    info(f"Downloaded {downloaded // 1024} KB")
                last_report = now


def _install_nuclei_windows_binary(assume_yes: bool = False) -> Tuple[bool, str]:
    install_dir = _default_windows_bin_dir()
    install_dir.mkdir(parents=True, exist_ok=True)

    info("Installing Nuclei v3 for Windows")
    info("Using prebuilt Windows AMD64 release binary")
    info("No Go compiler, CGO, GCC, or MinGW is required")

    try:
        info("Checking latest Nuclei release...")
        release = _fetch_json(NUCLEI_LATEST_RELEASE_API)
        version = str(release.get("tag_name") or "latest")
        asset_name, asset_url = _select_windows_nuclei_asset(release)
        info(f"Latest release: {version}")
        info(f"Downloading: {asset_name}")

        with tempfile.TemporaryDirectory(prefix="bladerecon-nuclei-") as tmp:
            archive = Path(tmp) / asset_name
            extract_dir = Path(tmp) / "extract"
            extract_dir.mkdir()
            _download_file(asset_url, archive)
            info("Extracting nuclei.exe...")
            with zipfile.ZipFile(archive) as zf:
                nuclei_member = next((name for name in zf.namelist() if Path(name).name.lower() == "nuclei.exe"), "")
                if not nuclei_member:
                    raise RuntimeError("nuclei.exe not found in release archive")
                zf.extract(nuclei_member, extract_dir)
                extracted = extract_dir / nuclei_member
                destination = install_dir / "nuclei.exe"
                shutil.copy2(extracted, destination)

        info(f"Installed nuclei.exe to {install_dir}")
        path_added = _ensure_windows_user_path(install_dir)
        if path_added:
            success(f"Added {install_dir} to user PATH")
            info("Restart PowerShell or CMD if the command is not visible in existing terminals.")

        ok, version_text, nuclei_exec = _validate_nuclei_install(install_dir)
        if not ok:
            return False, version_text
        success("Nuclei installed")
        console.print(f"[green]Version:[/] {version_text}")
        console.print(f"[green]Executable:[/] {nuclei_exec}")
        return True, version_text
    except Exception as exc:
        error(f"Windows Nuclei installation failed: {exc}")
        return False, str(exc)


def _command_output(cmd: List[str], timeout: int = 20) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout)
    except Exception as exc:
        return False, str(exc)
    output = "\n".join(part.strip() for part in (proc.stdout, proc.stderr) if part and part.strip())
    clean_output = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output)
    return proc.returncode == 0, clean_output.strip()


def _go_version(go_exec: Optional[str] = None) -> str:
    executable = go_exec or shutil.which("go")
    if not executable:
        return "Go not found on PATH"
    ok, output = _command_output([executable, "version"])
    return output if ok and output else str(executable)


def _nuclei_version(nuclei_exec: Optional[str] = None) -> str:
    executable = nuclei_exec or shutil.which("nuclei")
    if not executable:
        return "Run: bladerecon install-deps"
    ok, output = _command_output([executable, "-version", "-nc"])
    return output if ok and output else str(executable)


def _print_process_lines(prefix: str, text: str) -> None:
    for line in text.splitlines():
        clean = line.strip()
        if clean:
            info(f"{prefix}: {clean}")


def _run_with_progress(cmd: List[str], heartbeat_seconds: int = 20) -> subprocess.CompletedProcess[str]:
    info("Downloading Go dependencies...")
    info("Building Nuclei...")
    info("Waiting for Go installer...")
    info("This may take several minutes on first install.")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    output_lines: List[str] = []
    last_output = time.monotonic()
    last_heartbeat = time.monotonic()

    assert proc.stdout is not None
    while True:
        line = proc.stdout.readline()
        if line:
            output_lines.append(line)
            last_output = time.monotonic()
            _print_process_lines("go", line)
            continue
        if proc.poll() is not None:
            break
        now = time.monotonic()
        if now - last_heartbeat >= heartbeat_seconds:
            if now - last_output >= heartbeat_seconds:
                info("Installation still running...")
                info("Large dependency download or compilation may be in progress.")
            else:
                info("Go installer is still running...")
            last_heartbeat = now
        time.sleep(0.25)

    remaining = proc.stdout.read()
    if remaining:
        output_lines.append(remaining)
        _print_process_lines("go", remaining)
    return subprocess.CompletedProcess(cmd, int(proc.returncode or 0), "".join(output_lines), "")


def _validate_nuclei_install(go_bin_dir: Optional[Path]) -> Tuple[bool, str, Optional[str]]:
    nuclei_exec = shutil.which("nuclei")
    if not nuclei_exec and go_bin_dir:
        candidate = go_bin_dir / ("nuclei.exe" if platform.system() == "Windows" else "nuclei")
        if candidate.exists():
            nuclei_exec = str(candidate)
    if not nuclei_exec:
        return False, "nuclei executable not found on PATH or Go bin directory", None
    ok, version_text = _command_output([nuclei_exec, "-version", "-nc"])
    if not ok:
        return False, version_text or "nuclei -version failed", nuclei_exec
    return True, version_text or "version detected", nuclei_exec


def _install_nuclei_with_go(go_bin_dir: Optional[Path], assume_yes: bool) -> None:
    console.print("\n[bold]Installing Nuclei v3 via Go (go install)...[/]")
    go_exec = shutil.which("go") or "go"
    nuclei_cmd = [go_exec, "install", "-v", NUCLEI_INSTALL_TARGET]
    try:
        if not assume_yes:
            console.print("Running: " + " ".join(nuclei_cmd))
        info("Installing Nuclei v3")
        proc = _run_with_progress(nuclei_cmd)
        if proc.returncode == 0:
            ok, version_text, nuclei_exec = _validate_nuclei_install(go_bin_dir)
            if ok:
                success("Nuclei installed")
                console.print(f"[green]Version:[/] {version_text}")
                console.print(f"[green]Executable:[/] {nuclei_exec}")
            else:
                warn("Nuclei build completed, but executable validation failed")
                console.print(f"[yellow]{version_text}[/]")
                if go_bin_dir:
                    console.print(f"[yellow]Ensure Go bin is in PATH:[/] {go_bin_dir}")
        else:
            error("Nuclei installation failed")
            if proc.stdout:
                console.print(proc.stdout)
    except FileNotFoundError:
        console.print("[red]Go executable not found; cannot run go install. Skipping nuclei installation.[/]")


def _default_template_dir() -> Path:
    return Path(os.path.expanduser("~")) / "nuclei-templates"


def _bootstrap_nuclei_templates(template_dir: Optional[Path] = None, timeout: int = 300) -> Tuple[bool, str]:
    """Install templates with nuclei updater, falling back to git clone."""
    target = Path(template_dir or _default_template_dir()).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    updater_output = ""

    if shutil.which("nuclei"):
        try:
            proc = subprocess.run(
                ["nuclei", "-ut", "-update-template-dir", str(target)],
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
            updater_output = (proc.stdout or "") + (proc.stderr or "")
            if proc.returncode == 0 and nuclei_template_status(target)["ok"]:
                return True, "Templates installed via Nuclei Updater"
            if "context deadline exceeded" not in updater_output.lower() and "failed to download templates" not in updater_output.lower():
                info(f"Nuclei template updater did not complete cleanly: {updater_output.strip()[:240] or proc.returncode}")
        except subprocess.TimeoutExpired:
            updater_output = "context deadline exceeded"
        except Exception as exc:
            updater_output = str(exc)
    else:
        updater_output = "nuclei not found on PATH"

    if not shutil.which("git"):
        return False, f"Template updater failed and git is not available. Last updater output: {updater_output.strip()[:240]}"

    if target.exists() and any(target.iterdir()):
        status = nuclei_template_status(target)
        if status["ok"]:
            return True, f"Templates already available via {status['source']}"
        return False, f"Template directory exists but is incomplete: {target}. Move or clean it, then run bladerecon repair."

    try:
        clone_proc = subprocess.run(
            ["git", "clone", "--depth", "1", "https://github.com/projectdiscovery/nuclei-templates.git", str(target)],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except Exception as exc:
        return False, str(exc)
    clone_output = (clone_proc.stdout or "") + (clone_proc.stderr or "")
    if clone_proc.returncode == 0 and nuclei_template_status(target)["ok"]:
        return True, "Templates installed via Git Repository"
    return False, clone_output.strip() or f"git clone exited with {clone_proc.returncode}"


def _install_playwright_chromium() -> Tuple[bool, str]:
    cmd = [sys.executable, "-m", "playwright", "install", "chromium", "--with-deps"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if proc.returncode == 0:
        chromium_ok, chromium_detail = check_playwright_chromium()
        return chromium_ok, "Chromium installed and launch test passed" if chromium_ok else chromium_detail
    return False, output or f"playwright install exited with {proc.returncode}"


def _print_readiness_failures(title: str, failures: List[Any]) -> None:
    error(title)
    for failure in failures:
        detail = f"{failure.name}: {failure.status} - {failure.reason}"
        if failure.details:
            detail += f" ({failure.details})"
        info(detail)


def _ensure_readiness(requirements: List[str], output: Path, template_dir: Optional[Path] = None, auto_templates: bool = True) -> bool:
    failures = readiness_failures(requirements, output=output, template_dir=template_dir)
    template_failed = any(failure.name == "Nuclei Templates" for failure in failures)
    if template_failed and auto_templates:
        info("Nuclei templates unavailable; attempting automatic bootstrap")
        ok, message = _bootstrap_nuclei_templates(template_dir)
        if ok:
            success(message)
            failures = readiness_failures(requirements, output=output, template_dir=template_dir)
        else:
            warn(message)
    if failures:
        _print_readiness_failures("Readiness check failed", failures)
        info("Run: bladerecon repair")
        return False
    return True


def _custom_templates_available(path: Optional[Path]) -> bool:
    if not path or not path.exists():
        return False
    if path.is_file():
        return path.suffix.lower() in {".yaml", ".yml"}
    return any(path.rglob("*.yaml")) or any(path.rglob("*.yml"))


def _format_path_snippet(go_bin: Path, shell: str) -> str:
    """Return the PATH update snippet for the given shell."""
    if shell == "fish":
        return f"set -Ux PATH $PATH {go_bin}"
    return f"echo 'export PATH=$PATH:{go_bin}' >> ~/.{shell}rc"


def _print_path_helper(go_bin: Path, assume_yes: bool) -> None:
    """Print helper instructions for adding Go bin to PATH and optionally append it."""
    from rich.panel import Panel

    console.print(Panel.fit("Go binary directory detected", style="bold blue"))
    console.print(f"[green]Go bin directory:[/] {go_bin}")
    console.print("Add this directory to your PATH if it is not already present.")

    shell = os.path.basename(os.environ.get("SHELL", "bash"))
    shell = shell if shell in {"bash", "zsh", "fish"} else "bash"
    rc_path = Path.home() / f".{shell}rc"
    snippet = _format_path_snippet(go_bin, shell)

    console.print(Panel.fit(f"Shell detected: {shell}", style="bold yellow"))
    console.print("Use one of these commands:")
    console.print(f"[cyan]{snippet}[/]")

    if shell in {"bash", "zsh"}:
        if assume_yes:
            try:
                rc_text = rc_path.read_text(encoding="utf-8-sig") if rc_path.exists() else ""
                if str(go_bin) not in rc_text:
                    rc_path.write_text(rc_text + "\n" + snippet + "\n", encoding="utf-8")
                    console.print(f"[green]Updated {rc_path} automatically.[/]")
                else:
                    console.print(f"[green]{rc_path} already contains the path entry.[/]")
            except Exception as exc:
                console.print(f"[yellow]Unable to update {rc_path} automatically:[/] {exc}")
        else:
            if typer.confirm(f"Do you want BladeRecon to append this line to {rc_path}?", default=False):
                try:
                    rc_text = rc_path.read_text(encoding="utf-8-sig") if rc_path.exists() else ""
                    if str(go_bin) not in rc_text:
                        rc_path.write_text(rc_text + "\n" + snippet + "\n", encoding="utf-8")
                        console.print(f"[green]Added PATH entry to {rc_path}.[/]")
                    else:
                        console.print(f"[green]{rc_path} already contains the PATH entry.[/]")
                except Exception as exc:
                    console.print(f"[red]Unable to append to {rc_path}:[/] {exc}")
    elif shell == "fish":
        console.print("[yellow]For fish, run the command shown above in your fish shell.[/]")


@app.command()
def subdomain(
    domain: str = typer.Argument(..., help="Target domain, e.g. example.com"),
    output: Path = typer.Option(Path("results"), "-o", "--output", help="Output folder"),
    passive: bool = typer.Option(True, "--passive/--no-passive", help="Use passive sources (crt.sh, AlienVault)"),
    active: bool = typer.Option(False, "--active/--no-active", help="Enable active DNS bruteforce using common prefixes"),
    prefixes: Optional[Path] = typer.Option(None, "--prefixes", help="Optional prefixes wordlist for DNS brute"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP/HTTPS/SOCKS5 proxy for passive sources"),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Custom User-Agent for HTTP sources"),
    random_user_agent: bool = typer.Option(False, "--random-user-agent", help="Rotate a built-in User-Agent for this run"),
) -> None:
    """Collect subdomains for a given domain using multiple sources.

    Writes results to `<output>/<domain>/subdomains/subdomains.txt`.
    """
    try:
        from .modules import subdomains as submod  # type: ignore

        safe_domain = _require_domain("subdomain", domain)
        print_module_header("Subdomain Enumeration", safe_domain)
        submod.run(domain=safe_domain, output=output, passive=passive, active=active, prefixes_file=prefixes, proxy=proxy, user_agent=user_agent, random_user_agent=random_user_agent)
    except typer.Exit:
        raise
    except Exception as exc:
        error(f"Subdomain module error: {exc}")


@app.command()
def param(
    target: str = typer.Argument(..., help="Target domain or path to a file with URLs"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", help="Wordlist path to merge with discovered params"),
    output: Path = typer.Option(Path("results"), "-o", "--output"),
) -> None:
    """Discover URL parameters using Wayback (GAU-like) and a common wordlist.

    `target` can be a domain (example.com) or a file containing URLs (one per line).
    """
    try:
        from .modules import parameters as pmod  # type: ignore

        safe_target = target if Path(target).exists() else _require_domain("param", target)
        print_module_header("Parameter Discovery", safe_target)
        result = pmod.run(target=safe_target, output=output, wordlist=wordlist)
        if getattr(result, "status", "") == "skipped" and not Path(target).exists():
            update_scan_state(safe_target, output, "parameters", "skipped", 0.0, getattr(result, "reason", "Skipped"))
    except typer.Exit:
        raise
    except Exception as exc:
        error(f"Parameters module error: {exc}")


@app.command()
def probe(
    domain: Optional[str] = typer.Argument(None, help="Target domain, e.g. example.com"),
    list_file: Optional[Path] = typer.Option(None, "-l", "--list", help="File with hosts or URLs"),
    domain_option: Optional[str] = typer.Option(None, "-d", "--domain", hidden=True),
    output: Path = typer.Option(Path("results"), "-o", "--output"),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", help="Max concurrent HTTP probes"),
    timeout: Optional[int] = typer.Option(None, "--timeout", help="HTTP timeout in seconds"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP/HTTPS/SOCKS5 proxy"),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Custom User-Agent"),
    random_user_agent: bool = typer.Option(False, "--random-user-agent", help="Use a randomized built-in User-Agent"),
    profile: str = typer.Option("balanced", "--profile", help="Safety profile: safe, balanced, aggressive"),
) -> None:
    """Probe hosts over HTTP/HTTPS and save alive targets."""
    try:
        from .modules import probe as probemod  # type: ignore

        resolved_domain = _normalize_optional_target("probe", domain, domain_option)
        active_profile = normalize_scan_profile(profile)
        print_module_header("HTTP Probing", resolved_domain or str(list_file or "targets"))
        probemod.run(domain=resolved_domain, list_file=list_file, output=output, concurrency=concurrency, timeout=timeout, proxy=proxy, user_agent=user_agent, random_user_agent=random_user_agent, profile=active_profile)
    except typer.Exit:
        raise
    except Exception as exc:
        error(f"Probe module error: {exc}")


@app.command()
def js(
    domain: str = typer.Argument(..., help="Target domain, e.g. example.com"),
    output: Path = typer.Option(Path("results"), "-o", "--output"),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", help="Max concurrent HTTP requests"),
    timeout: Optional[int] = typer.Option(None, "--timeout", help="HTTP timeout in seconds"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP/HTTPS/SOCKS5 proxy"),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Custom User-Agent"),
    random_user_agent: bool = typer.Option(False, "--random-user-agent", help="Use a randomized built-in User-Agent"),
    profile: str = typer.Option("balanced", "--profile", help="Safety profile: safe, balanced, aggressive"),
) -> None:
    """Discover JavaScript files from alive hosts."""
    try:
        from .modules import js as jsmod  # type: ignore

        safe_domain = _require_domain("js", domain)
        active_profile = normalize_scan_profile(profile)
        print_module_header("JavaScript Recon", safe_domain)
        jsmod.run(domain=safe_domain, output=output, concurrency=concurrency, timeout=timeout, proxy=proxy, user_agent=user_agent, random_user_agent=random_user_agent, profile=active_profile)
    except typer.Exit:
        raise
    except Exception as exc:
        error(f"JavaScript module error: {exc}")


@app.command()
def endpoints(
    domain: str = typer.Argument(..., help="Target domain, e.g. example.com"),
    output: Path = typer.Option(Path("results"), "-o", "--output"),
) -> None:
    """Extract useful endpoints from downloaded JavaScript."""
    try:
        from .modules import endpoints as endpointmod  # type: ignore

        safe_domain = _require_domain("endpoints", domain)
        print_module_header("Endpoint Discovery", safe_domain)
        endpointmod.run(domain=safe_domain, output=output)
    except typer.Exit:
        raise
    except Exception as exc:
        error(f"Endpoint module error: {exc}")


@app.command()
def secrets(
    domain: str = typer.Argument(..., help="Target domain, e.g. example.com"),
    output: Path = typer.Option(Path("results"), "-o", "--output"),
) -> None:
    """Detect exposed secret patterns in downloaded JavaScript."""
    try:
        from .modules import secrets as secretmod  # type: ignore

        safe_domain = _require_domain("secrets", domain)
        print_module_header("Secret Discovery", safe_domain)
        secretmod.run(domain=safe_domain, output=output)
    except typer.Exit:
        raise
    except Exception as exc:
        error(f"Secret module error: {exc}")


@app.command()
def screenshot(
    domain: Optional[str] = typer.Argument(None, help="Target domain, e.g. example.com"),
    list_file: Optional[Path] = typer.Option(None, "-l", "--list", help="File with URLs (one per line)"),
    domain_option: Optional[str] = typer.Option(None, "-d", "--domain", hidden=True),
    output: Path = typer.Option(Path("results"), "-o", "--output"),
    full_page: bool = typer.Option(False, "--full-page", help="Capture full page screenshots"),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", help="Max concurrent pages"),
    profile: str = typer.Option("balanced", "--profile", help="Safety profile: safe, balanced, aggressive"),
) -> None:
    """Take screenshots using Playwright (async Chromium).

    Provide either `--domain` or `--list` (file with URLs). Requires Playwright browsers.
    """
    info("Screenshots use Playwright Chromium. Run 'bladerecon install-deps' if browsers are missing.")
    try:
        from .modules import screenshots as shots  # type: ignore

        resolved_domain = _normalize_optional_target("screenshot", domain, domain_option)
        active_profile = normalize_scan_profile(profile)
        if not _ensure_readiness(["Playwright", "Chromium", "Output Directories", "Permissions"], output, auto_templates=False):
            raise typer.Exit(1)
        print_module_header("Screenshot Capture", resolved_domain or str(list_file or "targets"))
        shots.run(domain=resolved_domain, list_file=list_file, output=output, full_page=full_page, concurrency=concurrency, profile=active_profile)
    except typer.Exit:
        raise
    except Exception as exc:
        error(f"Screenshots module error: {exc}")


@app.command()
def nuclei(
    domain: Optional[str] = typer.Argument(None, help="Target domain, e.g. example.com"),
    list_file: Optional[Path] = typer.Option(None, "-l", "--list", help="File with targets (one per line)"),
    domain_option: Optional[str] = typer.Option(None, "-d", "--domain", hidden=True),
    profile: str = typer.Option("balanced", "--profile", help="Scan profile: safe, balanced, aggressive"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Override comma-separated severities"),
    exclude_tags: Optional[str] = typer.Option(None, "--exclude-tags", help="Override comma-separated tags to exclude"),
    templates: Optional[Path] = typer.Option(None, "--templates", help="Custom templates path"),
    update_templates: bool = typer.Option(False, "--update-templates", help="Update nuclei templates before scanning"),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", help="Nuclei concurrency override"),
    timeout: Optional[int] = typer.Option(None, "--timeout", help="Optional module wall-clock timeout in seconds"),
    output: Path = typer.Option(Path("results"), "-o", "--output"),
) -> None:
    """Run Nuclei (wrapper). Requires nuclei binary in PATH.

    Provide either `--domain` or `--list`.
    """
    info("Nuclei wrapper using safe/balanced/aggressive profiles.")
    try:
        from .modules import nuclei as nmod  # type: ignore

        resolved_domain = _normalize_optional_target("nuclei", domain, domain_option)
        active_profile = normalize_scan_profile(profile)
        requirements = ["Nuclei Binary", "Output Directories", "Permissions"] if _custom_templates_available(templates) else ["Nuclei Binary", "Nuclei Templates", "Output Directories", "Permissions"]
        if not _ensure_readiness(requirements, output, None if _custom_templates_available(templates) else templates):
            raise typer.Exit(1)
        print_module_header("Nuclei Scan", resolved_domain or str(list_file or "targets"))
        nmod.run(domain=resolved_domain, list_file=list_file, profile=active_profile, severity=severity, exclude_tags=exclude_tags, templates=templates, update_templates=update_templates, concurrency=concurrency, timeout=timeout, output=output)
    except typer.Exit:
        raise
    except Exception as exc:
        error(f"Nuclei module error: {exc}")


@app.command()
def intelligence(
    domain: str = typer.Argument(..., help="Target domain, e.g. example.com"),
    output: Path = typer.Option(Path("results"), "-o", "--output"),
) -> None:
    """Generate intelligence artifacts from existing scan outputs."""
    try:
        from .modules import intelligence as intelmod  # type: ignore

        safe_domain = _require_domain("intelligence", domain)
        print_module_header("Recon Intelligence", safe_domain)
        result = intelmod.run(target=safe_domain, output=output)
        if getattr(result, "status", "") == "skipped":
            skip(f"Intelligence skipped: {getattr(result, 'reason', 'Skipped')}")
    except typer.Exit:
        raise
    except Exception as exc:
        error(f"Intelligence module error: {exc}")


@app.command()
def advanced(
    domain: str = typer.Argument(..., help="Target domain, e.g. example.com"),
    output: Path = typer.Option(Path("results"), "-o", "--output"),
    profile: str = typer.Option("balanced", "--profile", help="Safety profile: safe, balanced, aggressive"),
) -> None:
    """Generate advanced recon intelligence from existing scan outputs."""
    try:
        from .modules import advanced as advmod  # type: ignore

        safe_domain = _require_domain("advanced", domain)
        active_profile = normalize_scan_profile(profile)
        print_module_header("Advanced Recon", safe_domain)
        result = advmod.run(target=safe_domain, output=output, profile=active_profile)
        if getattr(result, "status", "") == "skipped":
            skip(f"Advanced recon skipped: {getattr(result, 'reason', 'Skipped')}")
    except typer.Exit:
        raise
    except Exception as exc:
        error(f"Advanced recon module error: {exc}")


@app.command()
def full(
    domain: str = typer.Argument(..., help="Target domain, e.g. example.com"),
    output: Path = typer.Option(Path("results"), "-o", "--output"),
    all: bool = typer.Option(True, "--all/--no-all", help="Run all modules (default: True)"),
    report: bool = typer.Option(True, "--report/--no-report", help="Generate report after full run (default: True)"),
    resume_mode: bool = typer.Option(False, "--resume", help="Skip completed modules from scan_state.json"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP/HTTPS/SOCKS5 proxy for HTTP-based modules"),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Custom User-Agent"),
    random_user_agent: bool = typer.Option(False, "--random-user-agent", help="Use a randomized built-in User-Agent"),
    profile: str = typer.Option("balanced", "--profile", help="Safety profile: safe, balanced, aggressive"),
) -> None:
    """Run the full recon pipeline.

    Pipeline: subdomains -> probe -> js -> endpoints -> secrets -> parameters
    -> intelligence -> advanced -> screenshots -> nuclei -> report.

    By default `--all` includes Nuclei.
    """
    domain = _require_domain("full", domain)
    active_profile = normalize_scan_profile(profile)
    info(f"Target acquired: {domain}")
    info(f"Safety profile: {active_profile}")
    requirements = ["Playwright", "Chromium", "Output Directories", "Permissions"]
    if all:
        requirements.extend(["Nuclei Binary", "Nuclei Templates"])
    if not _ensure_readiness(requirements, output):
        raise typer.Exit(1)

    from .modules import nuclei as nmod  # type: ignore
    from .modules import advanced as advmod  # type: ignore
    from .modules import endpoints as endpointmod  # type: ignore
    from .modules import js as jsmod  # type: ignore
    from .modules import intelligence as intelmod  # type: ignore
    from .modules import parameters as pmod  # type: ignore
    from .modules import probe as probemod  # type: ignore
    from .modules import report as rmod  # type: ignore
    from .modules import secrets as secretmod  # type: ignore
    from .modules import screenshots as shots  # type: ignore
    from .modules import subdomains as submod  # type: ignore
    from .modules.utils import load_scan_state, setup_logging

    workflow_output = resolve_latest_run_output_dir(output, domain) if resume_mode else create_scan_run_output_dir(output, domain, active_profile)
    info(f"Output run: {workflow_output}")

    if not resume_mode:
        scan_state_path(domain, workflow_output).unlink(missing_ok=True)
    log = setup_logging(domain, workflow_output, "full")
    state = load_scan_state(domain, workflow_output) if resume_mode else {}
    state["scan_profile"] = active_profile
    state["framework_version"] = __version__
    state.setdefault("report_version", "1")
    save_scan_state(domain, workflow_output, state)
    completed = set(state.get("completed_modules", []))
    scan_started = time.perf_counter()
    scan_monitor = PerformanceMonitor().start()
    steps = [
        ("subdomains", lambda: submod.run(domain=domain, output=workflow_output, proxy=proxy, user_agent=user_agent, random_user_agent=random_user_agent, resume=resume_mode)),
        ("probe", lambda: probemod.run(domain=domain, output=workflow_output, proxy=proxy, user_agent=user_agent, random_user_agent=random_user_agent, resume=resume_mode, profile=active_profile)),
        ("js", lambda: jsmod.run(domain=domain, output=workflow_output, proxy=proxy, user_agent=user_agent, random_user_agent=random_user_agent, resume=resume_mode, profile=active_profile)),
        ("endpoints", lambda: endpointmod.run(domain=domain, output=workflow_output, resume=resume_mode)),
        ("secrets", lambda: secretmod.run(domain=domain, output=workflow_output, resume=resume_mode)),
        ("parameters", lambda: pmod.run(target=domain, output=workflow_output, resume=resume_mode)),
        ("intelligence", lambda: intelmod.run(target=domain, output=workflow_output, resume=resume_mode)),
        ("advanced", lambda: advmod.run(target=domain, output=workflow_output, resume=resume_mode, profile=active_profile)),
        ("screenshots", lambda: shots.run(domain=domain, output=workflow_output, resume=resume_mode, profile=active_profile)),
    ]
    if all:
        steps.append(("nuclei", lambda: nmod.run(domain=domain, output=workflow_output, resume=resume_mode, profile=active_profile)))
    module_durations: List[float] = []
    module_titles = {
        "subdomains": "Subdomain Enumeration",
        "probe": "HTTP Probing",
        "js": "JavaScript Recon",
        "endpoints": "Endpoint Discovery",
        "secrets": "Secret Discovery",
        "parameters": "Parameter Discovery",
        "intelligence": "Recon Intelligence",
        "advanced": "Advanced Recon",
        "screenshots": "Screenshot Capture",
        "nuclei": "Nuclei Scan",
        "report": "Report Generation",
    }
    for step_index, (step_name, step) in enumerate(steps, 1):
        if resume_mode and step_name in completed:
            info(f"Skipping completed module: {step_name}")
            module_durations.append(0)
            continue
        step_started = time.perf_counter()
        module_monitor = PerformanceMonitor().start()
        try:
            print_module_header(module_titles.get(step_name, step_name.title()), domain)
            info(f"Starting {step_name} ({step_index}/{len(steps)})")
            result = step()
            step_duration = time.perf_counter() - step_started
            module_durations.append(step_duration)
            module_perf = module_monitor.stop()
            if getattr(result, "status", "") == "skipped":
                reason = getattr(result, "reason", "Skipped")
                update_scan_state(domain, workflow_output, step_name, "skipped", step_duration, reason, performance=module_perf)
                skip(f"Skipped {step_name} in {step_duration:.2f}s")
                info(f"Reason: {reason}")
                log.info("Step skipped: %s in %.2fs (%s)", step_name, step_duration, reason)
                continue
            if getattr(result, "status", "") == "failed":
                reason = getattr(result, "reason", "Failed")
                update_scan_state(domain, workflow_output, step_name, "failed", step_duration, reason, performance=module_perf)
                warn(f"Failed {step_name} in {step_duration:.2f}s")
                info(f"Reason: {reason}")
                log.warning("Step failed: %s in %.2fs (%s)", step_name, step_duration, reason)
                continue
            if getattr(result, "status", "") == "timed_out":
                reason = getattr(result, "reason", "Timed out")
                update_scan_state(domain, workflow_output, step_name, "timed_out", step_duration, reason, performance=module_perf)
                warn(f"Timed out {step_name} in {step_duration:.2f}s")
                info(f"Reason: {reason}")
                log.warning("Step timed out: %s in %.2fs (%s)", step_name, step_duration, reason)
                continue
            update_scan_state(domain, workflow_output, step_name, "completed", step_duration, performance=module_perf)
            success(f"Completed {step_name} in {step_duration:.2f}s")
            log.info("Step completed: %s in %.2fs", step_name, step_duration)
        except Exception as exc:
            step_duration = time.perf_counter() - step_started
            module_durations.append(step_duration)
            module_perf = module_monitor.stop()
            update_scan_state(domain, workflow_output, step_name, "failed", step_duration, str(exc), performance=module_perf)
            log.exception("Step failed: %s", step_name)
            warn(f"{step_name} failed; continuing: {exc}")

    duration = time.perf_counter() - scan_started
    scan_perf = scan_monitor.stop()
    write_scan_metadata(
        domain,
        workflow_output,
        duration_seconds=round(duration, 2),
        duration_human=f"{duration:.2f}s",
        performance={**scan_perf, **_collect_traffic_counts(domain, workflow_output)},
    )
    if report:
        report_started = time.perf_counter()
        report_monitor = PerformanceMonitor().start()
        try:
            print_module_header("Report Generation", domain)
            info("Starting report")
            rmod.run(domain, output=workflow_output, scan_duration=f"{duration:.2f}s")
            report_duration = time.perf_counter() - report_started
            update_scan_state(domain, workflow_output, "report", "completed", report_duration, performance=report_monitor.stop())
            success(f"Completed report in {report_duration:.2f}s")
        except Exception as exc:
            report_duration = time.perf_counter() - report_started
            update_scan_state(domain, workflow_output, "report", "failed", report_duration, str(exc), performance=report_monitor.stop())
            log.exception("Step failed: report")
            warn(f"report failed; continuing: {exc}")
    log.info("Full scan duration: %.2fs", duration)
    _print_slowest_modules(domain, workflow_output)
    print_scan_summary(_collect_summary(domain, workflow_output, f"{duration:.2f}s"))
    success("Full run completed")


@app.command("scan")
def scan(
    domain: str = typer.Argument(..., help="Target domain, e.g. example.com"),
    output: Path = typer.Option(Path("results"), "-o", "--output"),
    all: bool = typer.Option(True, "--all/--no-all", help="Run all modules (default: True)"),
    report: bool = typer.Option(True, "--report/--no-report", help="Generate report after full run (default: True)"),
    resume_mode: bool = typer.Option(False, "--resume", help="Skip completed modules from scan_state.json"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP/HTTPS/SOCKS5 proxy for HTTP-based modules"),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Custom User-Agent"),
    random_user_agent: bool = typer.Option(False, "--random-user-agent", help="Use a randomized built-in User-Agent"),
    profile: str = typer.Option("balanced", "--profile", help="Safety profile: safe, balanced, aggressive"),
) -> None:
    """Start the standard recon workflow.

    Alias for `full`, because first-time users naturally try
    `bladerecon scan target.com`.
    """
    warn("`scan` is an alias for `full`; running the standard workflow.")
    full(
        domain=domain,
        output=output,
        all=all,
        report=report,
        resume_mode=resume_mode,
        proxy=proxy,
        user_agent=user_agent,
        random_user_agent=random_user_agent,
        profile=profile,
    )


@app.command()
def resume(
    domain: Optional[str] = typer.Argument(None, help="Target domain, e.g. example.com"),
    domain_option: Optional[str] = typer.Option(None, "-d", "--domain", hidden=True),
    output: Path = typer.Option(Path("results"), "-o", "--output"),
) -> None:
    """Resume a full scan by skipping modules completed in scan_state.json."""
    resolved_domain = _require_domain("resume", domain, domain_option)
    full(
        domain=resolved_domain,
        output=output,
        all=True,
        report=True,
        resume_mode=True,
        proxy=None,
        user_agent=None,
        random_user_agent=False,
    )


@app.command()
def install_deps(
    assume_yes: bool = typer.Option(False, "--yes", "-y", help="Automatically accept install prompts where possible"),
) -> None:
    """Install required external dependencies: Nuclei and Playwright browsers.

    On Windows, Nuclei is installed from the prebuilt GitHub release binary.
    On Linux/macOS, Nuclei uses the Go install workflow.
    """
    from rich.panel import Panel

    console.print(Panel.fit("Installing external dependencies", title="BladeRecon - install-deps", style="bold green"))

    # 1) Install nuclei
    go_bin_dir: Optional[Path]
    if platform.system() == "Windows":
        go_bin_dir = _default_windows_bin_dir()
        console.print(f"[green]Windows install directory:[/] {go_bin_dir}")
        _install_nuclei_windows_binary(assume_yes=assume_yes)
    else:
        # Linux/macOS keep the Go-based install workflow.
        go_path = shutil.which("go")
        if go_path:
            console.print(f"[green]Go found:[/] {go_path}")
            console.print(f"[green]Go version:[/] {_go_version(go_path)}")
        else:
            console.print("[yellow]Go not found on PATH.[/]")
            if platform.system() == "Linux":
                console.print("Attempting to install Go via package manager (requires sudo)")
                pkg_cmd = None
                update_cmd = None
                if shutil.which("apt"):
                    pkg_cmd = ["sudo", "apt", "install", "-y", "golang-go"]
                    update_cmd = ["sudo", "apt", "update"]
                elif shutil.which("yum"):
                    pkg_cmd = ["sudo", "yum", "install", "-y", "golang"]
                elif shutil.which("pacman"):
                    pkg_cmd = ["sudo", "pacman", "-S", "go", "--noconfirm"]

                try:
                    if update_cmd:
                        subprocess.run(update_cmd, check=False)
                    if pkg_cmd:
                        subprocess.run(pkg_cmd, check=False)
                    else:
                        console.print("[yellow]No supported package manager found. Install Go manually: https://go.dev/dl/[/]")
                except Exception as exc:
                    console.print(f"[red]Failed to install Go automatically:[/] {exc}")
            else:
                console.print("[yellow]Automatic Go install is supported on Linux only. Please install Go manually: https://go.dev/dl/[/]")

            go_path = shutil.which("go")
            if go_path:
                console.print(f"[green]Go installed:[/] {go_path}")
                console.print(f"[green]Go version:[/] {_go_version(go_path)}")
            else:
                console.print("[red]Go still not available. Nuclei install will likely fail.[/]")

        go_bin_dir = _get_go_bin_path()
        if go_bin_dir:
            console.print(f"[green]Detected Go bin directory:[/] {go_bin_dir}")
        else:
            console.print("[yellow]Unable to determine Go bin directory. PATH helper will be limited.[/]")
        _install_nuclei_with_go(go_bin_dir, assume_yes)

    # 2) Install or recover nuclei templates
    console.print("\n[bold]Installing Nuclei templates...[/]")
    templates_ok, templates_message = _bootstrap_nuclei_templates()
    if templates_ok:
        console.print(f"[green]{templates_message}[/]")
    else:
        console.print(f"[yellow]Template install could not be completed:[/] {templates_message}")

    # 3) Install Playwright browsers
    console.print("\n[bold]Installing Playwright Chromium (with deps)...[/]")
    try:
        chromium_ok, chromium_message = _install_playwright_chromium()
        if chromium_ok:
            console.print("[green]Playwright Chromium installed successfully.[/]")
        else:
            console.print("[yellow]Playwright install returned non-zero exit code. Output:[/]")
            console.print(chromium_message)
    except Exception as exc:
        console.print(f"[red]Failed to install Playwright browsers:[/] {exc}")

    if go_bin_dir and platform.system() != "Windows":
        _print_path_helper(go_bin_dir, assume_yes)

    console.print(Panel.fit("install-deps finished. Review messages above for any errors.", style="bold green"))


@app.command()
def report(
    domain: str = typer.Argument(..., help="Target domain, e.g. example.com"),
    output: Path = typer.Option(Path("results"), "-o", "--output"),
) -> None:
    """Generate a combined Markdown and HTML report for a target.

    Reads results from `output/<domain>/` and writes reports under `reports/`.
    """
    try:
        from .modules import report as rmod  # type: ignore

        safe_domain = _require_domain("report", domain)
        print_module_header("Report Generation", safe_domain)
        rmod.run(safe_domain, output=output)
    except typer.Exit:
        raise
    except Exception as exc:
        error(f"Report module error: {exc}")


@app.command("version", hidden=True)
def version() -> None:
    """Show BladeRecon version and runtime details."""
    data = version_info(__version__)
    print_module_summary(
        "Runtime",
        {
            "Version": data["version"],
            "Build Date": data["build_date"],
            "Python": data["python"],
            "Platform": data["platform"],
        },
    )


@cache_app.command("info")
def cache_info(
    output: Path = typer.Option(Path("results"), "-o", "--output"),
) -> None:
    """Show cache size, sources, and age."""
    from rich.table import Table

    data = get_cache_info(output)
    table = Table(title="BladeRecon Cache", border_style="steel_blue1", box=ui_box())
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Location", data["path"])
    table.add_row("Files", str(data["files"]))
    table.add_row("Size", data["size_human"])
    table.add_row("Sources", ", ".join(data["sources"]) or "none")
    table.add_row("Newest Age", f"{data['newest_age_seconds']}s" if data["newest_age_seconds"] is not None else "No cache entries")
    table.add_row("Oldest Age", f"{data['oldest_age_seconds']}s" if data["oldest_age_seconds"] is not None else "No cache entries")
    console.print(table)


@cache_app.command("clear")
def cache_clear(
    output: Path = typer.Option(Path("results"), "-o", "--output"),
) -> None:
    """Clear BladeRecon cache files."""
    removed, skipped = clear_cache(output)
    success("Cache cleanup completed")
    print_module_summary(
        "Cache Cleanup",
        {
            "Location": output / ".cache",
            "Removed": removed,
            "Skipped": skipped,
        },
    )


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return len([line for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()])


def _collect_summary(domain: str, output: Path, duration: str) -> dict:
    target_dir = target_output_dir(output, domain)
    scan_state_path = target_dir / "scan_state.json"
    scan_state = {}
    if scan_state_path.exists():
        try:
            scan_state = json.loads(scan_state_path.read_text(encoding="utf-8-sig"))
        except Exception:
            scan_state = {}
    modules = scan_state.get("modules", {}) if isinstance(scan_state, dict) else {}
    nuclei_path = target_dir / "nuclei" / "results.jsonl"
    if not nuclei_path.exists():
        nuclei_path = target_dir / "nuclei" / "results.json"
    nuclei_count = 0
    if nuclei_path.exists():
        text = nuclei_path.read_text(encoding="utf-8-sig")
        if nuclei_path.suffix == ".json":
            try:
                data = json.loads(text)
                nuclei_count = len(data) if isinstance(data, list) else int(bool(data))
            except Exception:
                nuclei_count = 0
        else:
            for line in text.splitlines():
                try:
                    if json.loads(line):
                        nuclei_count += 1
                except Exception:
                    continue
    screenshot_count = len(list((target_dir / "screenshots").glob("*.png"))) if (target_dir / "screenshots").exists() else 0
    screenshot_state = modules.get("screenshots", {}) if isinstance(modules, dict) else {}
    nuclei_state = modules.get("nuclei", {}) if isinstance(modules, dict) else {}
    screenshot_status = "Skipped" if isinstance(screenshot_state, dict) and screenshot_state.get("status") == "skipped" else screenshot_count
    if isinstance(screenshot_state, dict) and screenshot_state.get("status") == "failed" and not screenshot_count:
        screenshot_status = "Failed"
    if isinstance(nuclei_state, dict) and nuclei_state.get("status") in {"skipped", "failed", "timed_out"}:
        nuclei_status = str(nuclei_state.get("status") or "skipped").title()
        if "templates unavailable" in str(nuclei_state.get("error") or "").lower():
            nuclei_status = "Skipped"
    elif not nuclei_path.exists():
        nuclei_status = "Not Run"
    else:
        nuclei_status = nuclei_count
    parameter_state = modules.get("parameters", {}) if isinstance(modules, dict) else {}
    parameter_status = "Skipped" if isinstance(parameter_state, dict) and parameter_state.get("status") == "skipped" else _count_lines(target_dir / "parameters" / "parameters.txt")
    risk_score = "Not Run"
    risk_path = target_dir / "intelligence" / "risk_score.json"
    if risk_path.exists():
        try:
            risk_data = json.loads(risk_path.read_text(encoding="utf-8-sig"))
            if isinstance(risk_data, dict):
                risk_score = f"{risk_data.get('score', 0)}/100 ({risk_data.get('level', 'Not classified')})"
        except Exception:
            risk_score = "Not Run"
    return {
        "Target": domain,
        "Duration": duration,
        "Subdomains Found": _count_lines(target_dir / "subdomains" / "subdomains.txt"),
        "Alive Hosts": _count_lines(target_dir / "probe" / "alive.txt"),
        "JavaScript Files": _count_lines(target_dir / "js" / "js_files.txt"),
        "Endpoints Found": _count_lines(target_dir / "endpoints" / "endpoints.txt"),
        "Secrets Detected": _count_lines(target_dir / "secrets" / "secrets.txt"),
        "Parameters Found": parameter_status,
        "Screenshots Captured": screenshot_status,
        "Nuclei Findings": nuclei_status,
        "Risk Score": risk_score,
        "Output Location": str(target_dir),
    }


@app.command()
def repair(
    output: Path = typer.Option(Path("results"), "-o", "--output"),
    templates: Optional[Path] = typer.Option(None, "--templates", help="Custom nuclei templates path"),
) -> None:
    """Repair recoverable dependency issues and re-run health checks."""
    from rich.table import Table

    console.print(Panel.fit("Repairing recoverable dependencies", title="BladeRecon Repair", style="bold green"))
    actions: Dict[str, str] = {}

    template_status = nuclei_template_status(templates)
    if not template_status["ok"]:
        ok, message = _bootstrap_nuclei_templates(templates)
        actions["Nuclei Templates"] = message if ok else f"FAILED: {message}"
    else:
        actions["Nuclei Templates"] = f"Already OK ({template_status['source']})"

    chromium_ok, chromium_detail = check_playwright_chromium()
    if not chromium_ok:
        ok, message = _install_playwright_chromium()
        actions["Chromium"] = message if ok else f"FAILED: {message}"
    else:
        actions["Chromium"] = f"Already OK ({chromium_detail})"

    try:
        output.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output, prefix=".doctor-", suffix=".tmp", delete=False) as handle:
            handle.write("ok")
            test_file = Path(handle.name)
        test_file.unlink(missing_ok=True)
        actions["Permissions"] = f"Writable: {output}"
    except Exception as exc:
        actions["Permissions"] = f"FAILED: {exc}"

    action_table = Table(title="Repair Actions", border_style="steel_blue1", box=ui_box())
    action_table.add_column("Dependency")
    action_table.add_column("Action")
    for name, message in actions.items():
        action_table.add_row(name, message)
    console.print(action_table)
    doctor(output=output, templates=templates)


@app.command()
def doctor(
    output: Path = typer.Option(Path("results"), "-o", "--output"),
    templates: Optional[Path] = typer.Option(None, "--templates", help="Custom nuclei templates path"),
) -> None:
    """Check local dependencies and common runtime requirements."""
    from rich.table import Table

    table = Table(title="BladeRecon Doctor", border_style="steel_blue1", box=ui_box())
    table.add_column("Dependency")
    table.add_column("Status")
    table.add_column("Version")
    table.add_column("Details")

    def status_style(status: str) -> str:
        if status == "OK":
            return "green"
        if status == "FAILED":
            return "red"
        return "yellow"

    for check in dependency_health(output=output, template_dir=templates):
        details = check.details or check.reason
        if check.reason and check.reason not in details:
            details = f"{check.reason} | {details}" if details else check.reason
        table.add_row(check.name, f"[{status_style(check.status)}]{check.status}[/]", check.version or "Not applicable", details)

    console.print(table)


if __name__ == "__main__":
    app()
