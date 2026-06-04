from pathlib import Path
from unittest.mock import patch

from bladerecon.modules import screenshots


def test_screenshot_preserves_chromium_validation_detail(tmp_path: Path) -> None:
    with patch(
        "bladerecon.modules.screenshots.check_playwright_chromium",
        return_value=(False, "Browser launch failed: Access denied"),
    ):
        result = screenshots.run(domain="example.com", output=tmp_path, concurrency=1)

    assert result.status == "skipped"
    assert result.reason == "Browser launch failed: Access denied"


def test_screenshot_failure_classifier_categorizes_common_errors() -> None:
    assert screenshots._classify_navigation_error(Exception("net::ERR_CERT_AUTHORITY_INVALID"), "domcontentloaded") == "SSL error"
    assert screenshots._classify_navigation_error(Exception("net::ERR_NAME_NOT_RESOLVED"), "domcontentloaded") == "DNS failure"
    assert screenshots._classify_navigation_error(Exception("net::ERR_TOO_MANY_REDIRECTS"), "domcontentloaded") == "Redirect loop"


def test_screenshot_filter_skips_probe_known_5xx_targets(tmp_path: Path) -> None:
    target = tmp_path / "example.com"
    (target / "probe").mkdir(parents=True)
    (target / "probe" / "probe.json").write_text(
        '[{"final_url":"https://ok.example.com","status_code":200,"title":"OK","content_length":100},'
        '{"final_url":"https://broken.example.com","status_code":503,"title":"Unavailable","content_length":100}]',
        encoding="utf-8",
    )

    selected = screenshots._filter_screenshot_targets(
        ["https://ok.example.com", "https://broken.example.com"],
        target,
        {"screenshots": {"skip_duplicate_titles": True, "skip_duplicate_content_lengths": False, "placeholder_titles": []}},
    )

    assert selected == ["https://ok.example.com"]
