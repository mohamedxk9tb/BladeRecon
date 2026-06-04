import json
from pathlib import Path

from bladerecon.modules import intelligence


def test_detect_technologies_from_probe_and_js():
    scan_data = {
        "technology_rows": [
            {
                "host": "www.example.com",
                "technologies": [
                    {"name": "React", "confidence": "High", "sources": ["HTML Fingerprint"], "evidence": ["data-reactroot"]}
                ],
            }
        ],
        "probe_rows": [
            {
                "url": "https://example.com",
                "server": "nginx",
                "technologies": ["PHP"],
                "title": "Example",
            }
        ],
        "js_rows": [{"url": "https://example.com/_next/static/app.js"}],
        "endpoint_rows": [],
    }

    names = {item["name"] for item in intelligence.detect_technologies(scan_data)}
    react = next(item for item in intelligence.detect_technologies(scan_data) if item["name"] == "React")
    nextjs = next(item for item in intelligence.detect_technologies(scan_data) if item["name"] == "Next.js")

    assert {"Nginx", "PHP", "Next.js"}.issubset(names)
    assert react["confidence"] == "High"
    assert nextjs["confidence"] == "Medium"
    assert "data-reactroot" in react["evidence"]


def test_weak_framework_text_stays_informational_for_template_selection():
    technologies = [
        {"name": "Laravel", "confidence": "Medium", "hosts": ["api.example.com"], "sources": ["Probe Fingerprint"], "evidence": ["Laravel"]},
        {"name": "PHP", "confidence": "High", "hosts": ["api.example.com"], "sources": ["Framework Header"], "evidence": ["PHP/8.2"]},
    ]

    result = intelligence.recommend_templates(technologies, [])

    assert "php" in result["selected_tags"]
    assert "laravel" not in result["selected_tags"]


def test_javascript_urls_do_not_create_java_detection():
    scan_data = {
        "technology_rows": [],
        "probe_rows": [],
        "js_rows": [{"url": "https://example.com/static/javascript/app.js"}],
        "endpoint_rows": [],
    }

    names = {item["name"] for item in intelligence.detect_technologies(scan_data)}

    assert "Java" not in names


def test_cloud_assets_and_risk_score():
    scan_data = {
        "endpoint_rows": [{"endpoint": "https://admin.example.com/login"}],
        "js_rows": [{"url": "https://cdn.example.com/app.js?src=demo.s3-us-east-1.amazonaws.com"}],
        "secret_rows": [{"type": "API Key"}],
        "parameters": ["id"] * 51,
        "nuclei_rows": [],
    }
    cloud_assets = intelligence.discover_cloud_assets(scan_data)
    risk = intelligence.calculate_risk(scan_data, [{"name": "WordPress"}], cloud_assets)

    assert cloud_assets[0]["type"] == "AWS S3"
    assert risk["score"] >= 50
    assert risk["level"] in {"Medium", "High"}


def test_intelligence_run_writes_expected_outputs(tmp_path: Path, monkeypatch):
    target = tmp_path / "example.com"
    (target / "probe").mkdir(parents=True)
    (target / "js").mkdir()
    (target / "endpoints").mkdir()
    (target / "secrets").mkdir()
    (target / "parameters").mkdir()
    (target / "subdomains").mkdir()
    (target / "nuclei").mkdir()
    (target / "probe" / "alive.txt").write_text("https://example.com\n", encoding="utf-8")
    (target / "probe" / "probe.json").write_text(
        json.dumps([{"url": "https://example.com", "server": "Apache", "technologies": ["PHP"]}]),
        encoding="utf-8",
    )
    (target / "parameters" / "parameters.txt").write_text("id\nredirect\n", encoding="utf-8")
    monkeypatch.setattr(intelligence, "_resolve_ip", lambda host: "192.0.2.10")
    monkeypatch.setattr(intelligence, "_reverse_dns", lambda ip: "example.test")
    monkeypatch.setattr(intelligence, "nuclei_template_status", lambda: {"template_count": 123})

    result = intelligence.run("example.com", output=tmp_path)

    assert result.status == "completed"
    assert (target / "technology" / "technology.json").exists()
    assert (target / "intelligence" / "risk_score.json").exists()
    template_data = json.loads((target / "intelligence" / "template_intelligence.json").read_text(encoding="utf-8"))
    assert "apache" in template_data["selected_tags"]
    assert "php" not in template_data["selected_tags"]


def test_intelligence_skips_without_valid_scan_artifacts(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(intelligence, "_resolve_ip", lambda host: "192.0.2.10")

    result = intelligence.run("never-scanned.example", output=tmp_path)

    assert result.status == "skipped"
    assert not (tmp_path / "never-scanned.example" / "intelligence" / "risk_score.json").exists()
