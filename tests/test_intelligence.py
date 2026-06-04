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


def test_investigation_priorities_promote_actionable_signals():
    scan_data = {
        "nuclei_rows": [{"host": "https://api.example.com", "info": {"severity": "high"}}],
        "secret_rows": [{"type": "API Key", "source": "https://example.com/app.js"}],
        "endpoint_rows": [{"endpoint": "https://example.com/graphql"}],
        "parameters": ["redirect_uri", "page"],
    }

    priorities = intelligence.build_investigation_priorities(scan_data, {"score": 0, "factors": []})

    assert priorities[0]["source"] == "nuclei"
    assert any(item["target"] == "https://example.com/graphql" for item in priorities)
    assert any(item["target"] == "redirect_uri" for item in priorities)


def test_opportunity_priorities_outrank_infrastructure_noise():
    scan_data = {
        "probe_rows": [
            *[
                {"url": f"https://cdn{i}.example.com", "cdn": "Cloudflare", "title": "Static"}
                for i in range(50)
            ],
            {"url": "https://api.example.com/admin", "title": "Admin Console"},
        ],
        "endpoint_rows": [
            {"endpoint": "https://api.example.com/graphql"},
            {"endpoint": "https://api.example.com/admin"},
        ],
        "content_discovery_rows": [],
        "historical_endpoints": [],
        "historical_diff": {},
        "parameters": [],
    }

    priorities = intelligence.build_opportunity_priorities(scan_data)

    assert priorities[0]["host"] == "api.example.com"
    assert priorities[0]["priority"] == "Critical Investigation"
    assert {"GraphQL", "Admin"}.issubset(set(priorities[0]["opportunity_types"]))
    assert not any(str(item["host"]).startswith("cdn") for item in priorities)


def test_opportunity_priorities_promote_swagger_with_parameters():
    scan_data = {
        "probe_rows": [{"url": "https://docs.example.com", "title": "API Docs"}],
        "endpoint_rows": [{"endpoint": "https://docs.example.com/swagger"}],
        "content_discovery_rows": [],
        "historical_endpoints": [],
        "historical_diff": {},
        "parameters": ["redirect_url", "id", "page"],
    }

    top = intelligence.build_opportunity_priorities(scan_data)[0]

    assert top["host"] == "docs.example.com"
    assert top["score"] >= 80
    assert top["confidence"] == "High"
    assert top["evidence_diversity"] >= 2
    assert top["correlation_strength"] >= 3
    assert "Parameters" in top["opportunity_types"]
    assert "Multiple independent observations" in top["priority_reason"]


def test_opportunity_priorities_promote_historical_live_api():
    scan_data = {
        "probe_rows": [{"url": "https://api.example.com"}],
        "endpoint_rows": [],
        "content_discovery_rows": [],
        "historical_endpoints": [],
        "historical_diff": {
            "historical_and_currently_alive": ["https://api.example.com/api/v1/users"],
            "removed_apis": [],
            "legacy_paths": [],
        },
        "parameters": [],
    }

    top = intelligence.build_opportunity_priorities(scan_data)[0]

    assert top["host"] == "api.example.com"
    assert "Historical" in top["opportunity_types"]
    assert top["confidence"] == "Medium"
    assert top["priority"] == "Focused Review"
    assert top["priority_reason"] == "Historical-only endpoint evidence requires live verification before active testing."


def test_historical_only_opportunities_are_capped_until_live_validation():
    scan_data = {
        "probe_rows": [],
        "endpoint_rows": [],
        "content_discovery_rows": [],
        "historical_endpoints": [
            {"endpoint": "https://api.example.com/api/v1/users"},
            {"endpoint": "https://api.example.com/admin"},
            {"endpoint": "https://api.example.com/graphql"},
        ],
        "historical_diff": {
            "historical_and_currently_alive": [],
            "removed_apis": ["https://api.example.com/api/v1/users"],
            "legacy_paths": ["https://api.example.com/admin"],
        },
        "parameters": [],
    }

    top = intelligence.build_opportunity_priorities(scan_data)[0]

    assert top["host"] == "api.example.com"
    assert top["confidence"] == "Medium"
    assert top["score"] <= 60
    assert top["priority"] == "Focused Review"
    assert top["priority_reason"] == "Historical-only endpoint evidence requires live verification before active testing."
    assert top["validation_strength"] == "None"
    assert "Historical-only or legacy path needs live verification" in top["negative_validation_signals"]


def test_historical_alive_endpoint_is_not_double_counted_as_removed_or_legacy():
    scan_data = {
        "probe_rows": [{"url": "https://www.example.com", "alive": True}],
        "endpoint_rows": [],
        "content_discovery_rows": [],
        "historical_endpoints": [],
        "historical_diff": {
            "historical_and_currently_alive": ["https://www.example.com/api/v1/key"],
            "removed_apis": ["https://www.example.com/api/v1/key"],
            "legacy_paths": ["https://www.example.com/api/v1/key"],
        },
        "parameters": [],
        "nuclei_rows": [],
    }

    top = intelligence.build_opportunity_priorities(scan_data)[0]

    evidence_sources = {row["source"] for row in top["evidence"]}
    assert "historical_alive" in evidence_sources
    assert "historical_removed" not in evidence_sources
    assert "historical_legacy" not in evidence_sources
    assert "Historical endpoint host is alive" in top["positive_validation_signals"]
    assert "Historical-only or legacy path needs live verification" not in top["negative_validation_signals"]


def test_single_keyword_does_not_outrank_correlated_opportunity():
    scan_data = {
        "probe_rows": [{"url": "https://admin.example.com"}],
        "endpoint_rows": [
            {"endpoint": "https://admin.example.com/admin"},
            {"endpoint": "https://api.example.com/swagger", "category": "Swagger/OpenAPI"},
        ],
        "content_discovery_rows": [{"url": "https://api.example.com/openapi.json", "path": "/openapi.json", "status_code": 200, "signal_score": 80}],
        "historical_endpoints": [],
        "historical_diff": {"historical_and_currently_alive": ["https://api.example.com/api/v1/users"]},
        "parameters": ["redirect_url", "id"],
    }

    priorities = intelligence.build_opportunity_priorities(scan_data)

    assert priorities[0]["host"] == "api.example.com"
    assert priorities[0]["confidence"] in {"High", "Very High"}
    admin = next(item for item in priorities if item["host"] == "admin.example.com")
    assert admin["confidence"] == "Low"


def test_opportunity_validation_distinguishes_confidence_from_observed_signals():
    scan_data = {
        "probe_rows": [
            {"url": "https://api.example.com", "alive": True, "title": "API Login"},
            {"url": "https://cdn.example.com", "alive": True, "cdn": "Cloudflare", "title": "Static"},
        ],
        "endpoint_rows": [
            {"endpoint": "https://api.example.com/graphql", "category": "GraphQL"},
            {"endpoint": "https://api.example.com/auth/login"},
            {"endpoint": "https://cdn.example.com/api"},
        ],
        "content_discovery_rows": [
            {"url": "https://api.example.com/graphql", "path": "/graphql", "status_code": 200, "signal_score": 95},
        ],
        "historical_endpoints": [{"endpoint": "https://api.example.com/graphql"}],
        "historical_diff": {
            "historical_and_currently_alive": ["https://api.example.com/api/v1/users"],
            "removed_apis": [],
            "legacy_paths": [],
        },
        "parameters": ["redirect_url", "id"],
        "nuclei_rows": [{"host": "https://api.example.com/graphql", "info": {"severity": "high"}}],
    }

    priorities = intelligence.build_opportunity_priorities(scan_data)
    api = next(item for item in priorities if item["host"] == "api.example.com")
    cdn = next(item for item in priorities if item["host"] == "cdn.example.com")

    assert api["confidence"] in {"High", "Very High"}
    assert api["validation_strength"] == "Strong"
    assert "High Nuclei finding" in api["positive_validation_signals"]
    assert "GraphQL path returned actionable response" in api["positive_validation_signals"]
    assert cdn["validation_strength"] in {"None", "Weak"}
    assert "CDN/WAF infrastructure indicator observed" in cdn["negative_validation_signals"]


def test_noise_assessment_marks_cdn_heavy_results():
    scan_data = {
        "alive_hosts": ["https://a.example.com", "https://b.example.com"],
        "probe_rows": [
            {"url": "https://a.example.com", "cdn": "Cloudflare"},
            {"url": "https://b.example.com", "waf": "Cloudflare"},
        ],
    }

    assessment = intelligence._noise_assessment(scan_data, {"assets": []}, [])

    assert assessment["noisy_infrastructure_ratio"] == 1.0
    assert "CDN/WAF-heavy" in assessment["assessment"]


def test_collect_infrastructure_reuses_probe_ips_without_live_dns(monkeypatch):
    scan_data = {
        "alive_hosts": ["https://www.example.com"],
        "probe_rows": [{"url": "https://www.example.com", "ip": "192.0.2.55", "cdn": "Cloudflare"}],
    }

    monkeypatch.setattr(intelligence, "_resolve_ip", lambda host: (_ for _ in ()).throw(AssertionError("live dns should not run")))
    monkeypatch.setattr(intelligence, "_reverse_dns", lambda ip: (_ for _ in ()).throw(AssertionError("reverse dns should not run")))

    result = intelligence.collect_infrastructure("example.com", scan_data)

    by_host = {row["host"]: row for row in result["assets"]}
    assert by_host["www.example.com"]["ip"] == "192.0.2.55"
    assert by_host["www.example.com"]["reverse_dns"] == ""


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
    assert (target / "intelligence" / "noise_assessment.json").exists()
    assert (target / "intelligence" / "investigation_priorities.json").exists()
    assert (target / "intelligence" / "opportunity_priorities.json").exists()
    template_data = json.loads((target / "intelligence" / "template_intelligence.json").read_text(encoding="utf-8"))
    assert "apache" in template_data["selected_tags"]
    assert "php" not in template_data["selected_tags"]


def test_intelligence_skips_without_valid_scan_artifacts(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(intelligence, "_resolve_ip", lambda host: "192.0.2.10")

    result = intelligence.run("never-scanned.example", output=tmp_path)

    assert result.status == "skipped"
    assert not (tmp_path / "never-scanned.example" / "intelligence" / "risk_score.json").exists()
