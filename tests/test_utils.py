from pathlib import Path
from unittest.mock import Mock, patch

from bladerecon.modules import utils


def test_wordlist_loading_ignores_comments_empty_and_duplicates(tmp_path: Path) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("\n# comment\napi\napi\n admin \n", encoding="utf-8")

    assert utils.read_wordlist(wordlist) == ["api", "admin"]


def test_normalize_target_accepts_urls_and_strips_paths() -> None:
    assert utils.normalize_target("target.com") == "target.com"
    assert utils.normalize_target("https://target.com") == "target.com"
    assert utils.normalize_target("https://target.com/path?q=1") == "target.com"


def test_normalize_target_rejects_path_traversal_and_absolute_paths() -> None:
    for target in ("../target.com", "..\\target.com", "/tmp/target.com", "C:\\temp\\target.com"):
        try:
            utils.normalize_target(target)
        except ValueError:
            continue
        raise AssertionError(f"unsafe target accepted: {target}")


def test_prepare_module_output_clears_stale_files_unless_resuming(tmp_path: Path) -> None:
    stale = tmp_path / "example.com" / "probe" / "alive.txt"
    stale.parent.mkdir(parents=True)
    stale.write_text("https://old.example.com\n", encoding="utf-8")

    out_dir = utils.prepare_module_output(tmp_path, "example.com", "probe")

    assert out_dir == (tmp_path / "example.com" / "probe").resolve()
    assert not stale.exists()

    fresh = out_dir / "alive.txt"
    fresh.write_text("https://new.example.com\n", encoding="utf-8")
    utils.prepare_module_output(tmp_path, "example.com", "probe", resume=True)

    assert fresh.exists()


def test_scan_state_tracks_completed_and_failed_modules(tmp_path: Path) -> None:
    utils.update_scan_state("example.com", tmp_path, "probe", "completed", 1.25)
    utils.update_scan_state("example.com", tmp_path, "nuclei", "failed", 0.5, "missing binary")

    state = utils.load_scan_state("example.com", tmp_path)
    assert state["scan_id"]
    assert state["scan_profile"] == "standard"
    assert state["framework_version"]
    assert state["report_version"] == utils.REPORT_VERSION
    assert "probe" in state["completed_modules"]
    assert "nuclei" in state["failed_modules"]
    assert state["modules"]["nuclei"]["error"] == "missing binary"


def test_scan_state_moves_completed_module_to_failed(tmp_path: Path) -> None:
    utils.update_scan_state("example.com", tmp_path, "nuclei", "completed", 1.0)
    utils.update_scan_state("example.com", tmp_path, "nuclei", "failed", 0.5, "templates unavailable")

    state = utils.load_scan_state("example.com", tmp_path)
    assert "nuclei" not in state["completed_modules"]
    assert "nuclei" in state["failed_modules"]


def test_nuclei_template_status_accepts_updater_store(tmp_path: Path) -> None:
    template_dir = tmp_path / "nuclei-templates"
    template_dir.mkdir()
    (template_dir / ".checksum").write_text("ok", encoding="utf-8")
    (template_dir / "http").mkdir()
    (template_dir / "http" / "test.yaml").write_text("id: test\ninfo:\n  name: test\n", encoding="utf-8")

    status = utils.nuclei_template_status(template_dir)

    assert status["ok"] is True
    assert status["status"] == "OK"
    assert status["source"] == "Nuclei Updater"


def test_nuclei_template_status_accepts_git_store_without_checksum(tmp_path: Path) -> None:
    template_dir = tmp_path / "nuclei-templates"
    template_dir.mkdir()
    (template_dir / ".git").mkdir()
    (template_dir / "dns").mkdir()
    (template_dir / "dns" / "test.yaml").write_text("id: test\ninfo:\n  name: test\n", encoding="utf-8")

    status = utils.nuclei_template_status(template_dir)

    assert status["ok"] is True
    assert status["status"] == "OK"
    assert status["source"] == "Git Repository"
    assert status["template_count"] == 1


def test_nuclei_template_status_marks_empty_directory_missing(tmp_path: Path) -> None:
    template_dir = tmp_path / "nuclei-templates"
    template_dir.mkdir()

    status = utils.nuclei_template_status(template_dir)

    assert status["ok"] is False
    assert status["status"] == "MISSING"


def test_nuclei_template_status_warns_for_partial_directory(tmp_path: Path) -> None:
    template_dir = tmp_path / "nuclei-templates"
    template_dir.mkdir()
    (template_dir / "misc").mkdir()
    (template_dir / "misc" / "test.yaml").write_text("id: test\ninfo:\n  name: test\n", encoding="utf-8")

    status = utils.nuclei_template_status(template_dir)

    assert status["ok"] is False
    assert status["status"] == "WARN"
    assert "categories" in status["missing"]
    assert ".checksum" not in status["missing"]


def test_nuclei_template_status_accepts_custom_template_directory(tmp_path: Path) -> None:
    template_dir = tmp_path / "custom-templates"
    template_dir.mkdir()
    (template_dir / "local.yaml").write_text("id: local\n", encoding="utf-8")

    status = utils.nuclei_template_status(template_dir, require_checksum=False)

    assert status["ok"] is True
    assert status["template_count"] == 1
    assert "categories" not in status["missing"]


def test_clear_cache_handles_read_only_files(tmp_path: Path) -> None:
    cache_file = tmp_path / ".cache" / "urlscan" / "example.com.json"
    cache_file.parent.mkdir(parents=True)
    cache_file.write_text("{}", encoding="utf-8")
    cache_file.chmod(0o444)

    removed, skipped = utils.clear_cache(tmp_path)

    assert removed >= 1
    assert skipped == 0
    assert not (tmp_path / ".cache").exists()


def test_chromium_check_warns_when_executable_missing() -> None:
    chromium = Mock()
    chromium.executable_path = str(Path("missing-chromium"))
    playwright = Mock()
    playwright.chromium = chromium
    manager = Mock()
    manager.__enter__ = Mock(return_value=playwright)
    manager.__exit__ = Mock(return_value=False)

    with patch("importlib.util.find_spec", return_value=True), patch("playwright.sync_api.sync_playwright", return_value=manager):
        ok, detail = utils.check_playwright_chromium()

    assert ok is False
    assert detail == "Chromium browser not installed"
