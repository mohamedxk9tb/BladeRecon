import json
from pathlib import Path

from bladerecon.modules import advanced


def test_historical_url_normalization_keeps_in_scope_urls() -> None:
    assert advanced._normalize_historical_url("HTTPS://API.Example.com//api/v1/users?id=1", "example.com") == "https://api.example.com/api/v1/users?id=1"
    assert advanced._normalize_historical_url("https://evil.test/api", "example.com") == ""


def test_historical_url_normalization_skips_malformed_ipv6_url() -> None:
    assert advanced._normalize_historical_url("https://[2001:db8::1/api", "example.com") == ""


def test_historical_correlation_detects_removed_legacy_endpoint(tmp_path: Path) -> None:
    target = tmp_path / "example.com"
    (target / "endpoints").mkdir(parents=True)
    (target / "historical").mkdir()
    (target / "endpoints" / "endpoints.json").write_text(
        json.dumps([{"endpoint": "https://example.com/api/v2/users"}]),
        encoding="utf-8",
    )
    (target / "historical" / "endpoints.json").write_text(
        json.dumps([{"endpoint": "https://example.com/api/v1/users"}]),
        encoding="utf-8",
    )

    diff = advanced.correlate_historical("example.com", tmp_path)

    assert diff["legacy_paths"] == ["https://example.com/api/v1/users"]
    assert "https://example.com/api/v1/users" in diff["potentially_forgotten_assets"]
    assert (target / "historical_diff.json").exists()


def test_security_header_assets_classify_csp_hosts() -> None:
    rows = advanced._extract_header_assets(
        {"content-security-policy": "default-src 'self'; connect-src https://api.example.com https://login.okta.com; img-src https://cdn.example.net"},
        "example.com",
        "https://example.com",
    )

    by_host = {row["asset"]: row["type"] for row in rows}
    assert by_host["api.example.com"] == "In Scope"
    assert by_host["login.okta.com"] == "Authentication"
    assert by_host["cdn.example.net"] == "CDN"


def test_asset_priority_scores_high_interest_assets(tmp_path: Path) -> None:
    target = tmp_path / "example.com"
    (target / "probe").mkdir(parents=True)
    (target / "endpoints").mkdir()
    (target / "content_discovery").mkdir()
    (target / "nuclei").mkdir()
    (target / "probe" / "alive.txt").write_text("https://admin.example.com\n", encoding="utf-8")
    (target / "probe" / "probe.json").write_text(
        json.dumps([{"url": "https://admin.example.com", "title": "Admin Login"}]),
        encoding="utf-8",
    )
    (target / "endpoints" / "endpoints.json").write_text(
        json.dumps([{"endpoint": "https://admin.example.com/api/auth/login"}]),
        encoding="utf-8",
    )
    (target / "content_discovery" / "interesting_paths.json").write_text(
        json.dumps([{"url": "https://admin.example.com/admin", "signal": "High"}]),
        encoding="utf-8",
    )
    (target / "nuclei" / "results.json").write_text(
        json.dumps([{"host": "https://admin.example.com", "info": {"severity": "high"}}]),
        encoding="utf-8",
    )

    priority = advanced.build_asset_priority("example.com", tmp_path)

    top = priority["top_assets"][0]
    assert top["asset"] == "admin.example.com"
    assert top["score"] >= 90
    assert "High-interest endpoint" in top["reasons"]
    assert top["confidence"] == "High"
    assert top["strongest_factors"]
    assert any(item["signal"] == "nuclei_finding" for item in top["signal_details"])


def test_content_signal_scores_noise_lower_than_admin_paths() -> None:
    admin = advanced._content_signal("/admin", 200)
    test_path = advanced._content_signal("/test", 200)
    forbidden = advanced._content_signal("/debug", 403)

    assert admin["level"] == "High"
    assert test_path["level"] == "Low"
    assert forbidden["score"] >= 45
