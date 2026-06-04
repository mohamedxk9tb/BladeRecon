import json
from pathlib import Path

from bladerecon.modules import report


def test_asset_data_uri_skips_large_embedded_assets(tmp_path: Path) -> None:
    large = tmp_path / "large.png"
    large.write_bytes(b"x" * 2_600_000)

    assert report._asset_data_uri(large) == ""


def test_investigation_campaigns_group_api_opportunities_without_noise() -> None:
    targets = [
        {
            "target": "api.example.com",
            "type": "GraphQL",
            "opportunity_types": ["GraphQL", "API", "Authentication"],
            "score": 96,
            "confidence": "Very High",
            "validation_strength": "Strong",
            "positive_validation_signals": ["GraphQL access observed in endpoint artifacts", "High Nuclei finding"],
            "negative_validation_signals": ["No modern equivalent missing"],
            "correlation_strength": 6,
            "evidence_summary": ["GraphQL endpoint evidence", "Authentication surface nearby"],
            "evidence": [
                {"type": "GraphQL", "value": "https://api.example.com/graphql", "source": "endpoint", "reason": "GraphQL endpoint discovered"},
                {"type": "Authentication", "value": "https://api.example.com/auth/login", "source": "endpoint", "reason": "Authentication endpoint discovered"},
            ],
        },
        {
            "target": "docs.example.com",
            "type": "API",
            "opportunity_types": ["API", "Parameters"],
            "score": 88,
            "confidence": "High",
            "validation_strength": "Moderate",
            "positive_validation_signals": ["OpenAPI/Swagger access confirmed"],
            "negative_validation_signals": ["No Nuclei validation findings for this host"],
            "correlation_strength": 4,
            "evidence_summary": ["API/OpenAPI exposure evidence", "Sensitive parameter names observed"],
            "evidence": [
                {"type": "API", "value": "https://docs.example.com/swagger", "source": "endpoint", "reason": "API documentation discovered"},
                {"type": "Parameters", "value": "redirect_url", "source": "parameters", "reason": "Risky parameter names observed"},
            ],
        },
        {
            "target": "cdn.example.com",
            "type": "Priority asset",
            "reason": "Cloudflare CDN edge",
            "score": 10,
            "evidence": [],
        },
    ]

    campaigns = report._build_investigation_campaigns(targets)

    assert campaigns[0]["name"] == "API Ecosystem"
    assert campaigns[0]["opportunity_count"] == 2
    assert campaigns[0]["confidence"] == "Very High"
    assert campaigns[0]["average_confidence"] == "High"
    assert campaigns[0]["validation_strength"] in {"Moderate", "Strong"}
    assert "High Nuclei finding" in campaigns[0]["positive_validation_signals"]
    assert "No Nuclei validation findings for this host" in campaigns[0]["negative_validation_signals"]
    assert not any(item["name"] == "Infrastructure" for item in campaigns)


def test_report_rendering_with_minimal_outputs(tmp_path: Path) -> None:
    target = tmp_path / "example.com"
    (target / "subdomains").mkdir(parents=True)
    (target / "probe").mkdir()
    (target / "parameters").mkdir()
    (target / "js").mkdir()
    (target / "endpoints").mkdir()
    (target / "secrets").mkdir()
    (target / "nuclei").mkdir()
    (target / "screenshots").mkdir()
    (target / "technologies").mkdir()
    (target / "subdomains" / "subdomains.txt").write_text("www.example.com\n", encoding="utf-8")
    (target / "subdomains" / "subdomains.json").write_text(
        '[{"subdomain":"www.example.com","sources":["rapiddns","urlscan"]}]',
        encoding="utf-8",
    )
    (target / "probe" / "alive.txt").write_text("https://www.example.com\n", encoding="utf-8")
    (target / "probe" / "probe.json").write_text(
        '[{"url":"https://www.example.com","final_url":"https://www.example.com","alive":true,"technologies":["Nginx","Cloudflare"],"cdn":"Cloudflare","waf":"Cloudflare","server":"nginx/1.30.1"}]',
        encoding="utf-8",
    )
    (target / "parameters" / "parameters.txt").write_text("id\ntoken\n", encoding="utf-8")
    (target / "parameters" / "parameters_from_urls.txt").write_text("id\n", encoding="utf-8")
    (target / "js" / "js_files.json").write_text(
        '[{"url":"https://www.example.com/app.js","source_page":"https://www.example.com"}]',
        encoding="utf-8",
    )
    (target / "endpoints" / "endpoints.json").write_text(
        '[{"endpoint":"https://www.example.com/api/users","source":"https://www.example.com/app.js"}]',
        encoding="utf-8",
    )
    (target / "secrets" / "secrets.json").write_text(
        '[{"type":"Google API Key","value":"AIzaSyD-abcdefghijklmnopqrstuvwxyz01234","source":"https://www.example.com/app.js"}]',
        encoding="utf-8",
    )
    (target / "nuclei" / "results.jsonl").write_text("", encoding="utf-8")
    (target / "nuclei" / "metadata.json").write_text(
        '{"coverage_strategy":"smart_tags_plus_lightweight_baseline","baseline_scan":{"enabled":true,"applied":true,"status":"completed","severity":"critical,high"},"templates_executed":12,"templates_skipped":3,"duration_seconds":2.5,"findings_count":0}',
        encoding="utf-8",
    )
    (target / "screenshots" / "www.example.com.png").write_text("fake", encoding="utf-8")
    (target / "logs").mkdir()
    (target / "logs" / "scan_meta.json").write_text(
        '{"duration_human":"12.34s","performance":{"scan_start_time":"2026-05-31T10:00:00Z","scan_end_time":"2026-05-31T10:00:12Z","peak_ram_mb":88.5,"average_ram_mb":72.25,"peak_cpu_percent":41.2,"average_cpu_percent":12.3,"total_requests_sent":3,"total_responses_received":2}}',
        encoding="utf-8",
    )
    (target / "scan_state.json").write_text(
        '{"modules":{"probe":{"status":"completed","duration_seconds":1.25,"performance":{"peak_ram_mb":80.0,"average_ram_mb":70.0}},"nuclei":{"status":"completed","duration_seconds":2.5,"performance":{"peak_ram_mb":88.5,"average_ram_mb":75.0}}}}',
        encoding="utf-8",
    )
    (target / "technologies" / "technologies.json").write_text(
        '[{"host":"www.example.com","url":"https://www.example.com","detected":["Nginx","Cloudflare","nginx/1.30.1"],"technologies":[{"name":"Nginx","confidence":"High","sources":["Server Header"],"evidence":["nginx/1.30.1"]},{"name":"Cloudflare","confidence":"High","sources":["CDN Header"],"evidence":["cf-ray"]}]}]',
        encoding="utf-8",
    )
    (target / "intelligence").mkdir()
    (target / "intelligence" / "risk_score.json").write_text(
        '{"score":42,"level":"Medium","factors":["Large parameter surface"]}',
        encoding="utf-8",
    )
    (target / "intelligence" / "infrastructure.json").write_text(
        '{"assets":[{"host":"www.example.com","ip":"192.0.2.10","provider":"Cloudflare"}]}',
        encoding="utf-8",
    )
    (target / "intelligence" / "cloud_assets.json").write_text(
        '[{"type":"AWS CloudFront","value":"d111111abcdef8.cloudfront.net"}]',
        encoding="utf-8",
    )
    (target / "intelligence" / "historical_dns.json").write_text(
        '{"historical_hosts":["old.example.com"]}',
        encoding="utf-8",
    )
    (target / "intelligence" / "template_intelligence.json").write_text(
        '{"templates_available":123,"selected_tags":["nginx","php"],"selected":[{"reason":"PHP","tags":["php"]}]}',
        encoding="utf-8",
    )
    (target / "intelligence" / "opportunity_priorities.json").write_text(
        json.dumps(
            [
                {
                    "host": "www.example.com",
                    "opportunity_type": "Admin",
                    "opportunity_types": ["Admin", "API", "Parameters"],
                    "score": 92,
                    "priority": "Critical Investigation",
                    "confidence": "Very High",
                    "validation_strength": "Moderate",
                    "validation_score": 3,
                    "positive_validation_signals": ["Interesting response pattern observed (403)"],
                    "negative_validation_signals": ["No Nuclei validation findings for this host"],
                    "indicator_count": 4,
                    "evidence_diversity": 3,
                    "correlation_strength": 5,
                    "evidence_summary": ["Administrative surface evidence", "API/OpenAPI exposure evidence", "Sensitive parameter names observed"],
                    "priority_reason": "API exposure combines with risky parameters, increasing the likelihood of IDOR, redirect, traversal, or authorization findings.",
                    "suggested_testing": "Access control, endpoint authorization, IDOR testing",
                    "evidence": [
                        {"type": "Admin", "value": "https://www.example.com/admin", "score": 55, "reason": "Focused content discovery found administrative surface"}
                    ],
                }
                ,
                {
                    "host": "api.example.com",
                    "opportunity_type": "GraphQL",
                    "opportunity_types": ["GraphQL", "API", "Authentication", "Parameters"],
                    "score": 96,
                    "priority": "Critical Investigation",
                    "confidence": "Very High",
                    "validation_strength": "Strong",
                    "validation_score": 7,
                    "positive_validation_signals": ["GraphQL access observed in endpoint artifacts", "Auth-related endpoint discovered"],
                    "negative_validation_signals": ["No Nuclei validation findings for this host"],
                    "indicator_count": 5,
                    "evidence_diversity": 4,
                    "correlation_strength": 6,
                    "evidence_summary": ["GraphQL endpoint evidence", "Authentication surface nearby", "Sensitive parameter names observed"],
                    "priority_reason": "Multiple independent observations support manual investigation.",
                    "suggested_testing": "Introspection, authorization testing, IDOR testing",
                    "evidence": [
                        {"type": "GraphQL", "value": "https://api.example.com/graphql", "score": 65, "reason": "GraphQL endpoint discovered", "source": "endpoint"},
                        {"type": "Authentication", "value": "https://api.example.com/auth/login", "score": 35, "reason": "Authentication endpoint discovered", "source": "endpoint"},
                        {"type": "Parameters", "value": "redirect_url, id", "score": 20, "reason": "Risky parameter names observed", "source": "parameters"}
                    ],
                },
                {
                    "host": "docs.example.com",
                    "opportunity_type": "API",
                    "opportunity_types": ["API", "Parameters"],
                    "score": 88,
                    "priority": "High Investigation",
                    "confidence": "High",
                    "validation_strength": "Moderate",
                    "validation_score": 4,
                    "positive_validation_signals": ["OpenAPI/Swagger access confirmed"],
                    "negative_validation_signals": [],
                    "indicator_count": 3,
                    "evidence_diversity": 3,
                    "correlation_strength": 4,
                    "evidence_summary": ["API/OpenAPI exposure evidence", "Sensitive parameter names observed"],
                    "priority_reason": "API exposure combines with risky parameters.",
                    "suggested_testing": "Authorization testing, version diffing, parameter tampering",
                    "evidence": [
                        {"type": "API", "value": "https://docs.example.com/swagger", "score": 55, "reason": "API documentation discovered", "source": "endpoint"},
                        {"type": "API", "value": "https://docs.example.com/openapi.json", "score": 24, "reason": "OpenAPI path returned actionable response", "source": "content_response"}
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    (target / "historical").mkdir()
    (target / "historical" / "urls.json").write_text('[{"url":"https://www.example.com/old","sources":["wayback"]}]', encoding="utf-8")
    (target / "historical" / "endpoints.json").write_text('[{"endpoint":"https://www.example.com/api/v1/users"}]', encoding="utf-8")
    (target / "historical_diff.json").write_text(
        '{"historical_and_currently_alive":["https://www.example.com/api/v1/users"],"historical_only":[],"historical_unresolved":[],"removed_apis":["https://www.example.com/api/v1/users"],"legacy_paths":["https://www.example.com/api/v1/users"]}',
        encoding="utf-8",
    )
    (target / "content_discovery").mkdir()
    (target / "content_discovery" / "interesting_paths.json").write_text(
        '[{"url":"https://www.example.com/admin","path":"/admin","status_code":403,"signal":"High","signal_score":90,"reason":"administrative path keyword; access-controlled response"}]',
        encoding="utf-8",
    )
    (target / "asset_priority.json").write_text(
        '{"asset_count":1,"top_assets":[{"asset":"www.example.com","score":88,"confidence":"High","reasons":["Alive HTTP service","Interesting content discovery path"],"strongest_factors":[{"signal":"interesting_content","points":20,"confidence":"High","reason":"Interesting content discovery path"}],"signal_details":[{"signal":"alive_http","points":20,"confidence":"High","reason":"Alive HTTP service"}]}]}',
        encoding="utf-8",
    )

    report.run("example.com", output=tmp_path)

    assert (target / "reports" / "report.md").exists()
    html = (target / "reports" / "report.html").read_text(encoding="utf-8")
    assert "Attack Surface Summary" in html
    assert "RapidDNS" in html
    assert "URLScan" in html
    assert "JavaScript Files" in html
    assert "Technology Overview" in html
    assert "Recon Intelligence" in html
    assert "Advanced Recon Intelligence" in html
    assert "Top Investigation Targets" in html
    assert "Top Investigation Campaigns" in html
    assert "API Ecosystem" in html
    assert "Authorization testing, IDOR, version diffing" in html
    assert "Critical Investigation" in html
    assert "Very High confidence" in html
    assert "Strong validation" in html
    assert "GraphQL access observed in endpoint artifacts" in html
    assert "Evidence sources" in html
    assert "Access control, endpoint authorization, IDOR testing" in html
    assert "High confidence" in html
    assert "Coverage strategy: smart_tags_plus_lightweight_baseline" in html
    assert "Risk Score" in html
    assert "42/100" in html
    assert "Infrastructure Intelligence" in html
    assert "Cloud Assets" in html
    assert "Smart Nuclei Summary" in html
    assert "Technologies Detected" in html
    assert "Technology Categories" in html
    assert "Technology Evidence" in html
    assert "<th>Technology</th>" in html
    assert "Server Header" in html
    assert "Nginx 1.30.1" in html
    assert "Cloudflare: CDN / WAF" in html
    assert "Server: cloudflare" not in html
    assert "https://www.example.com/api/users" in html
    assert "REST APIs" in html
    assert "Google API Key" in html
    assert "Secret Type" in html
    assert "Confidence" in html
    assert "Value Preview" in html
    assert "Risk Level" in html
    assert "Discovered Parameters" in html
    assert "Candidate Parameters" in html
    assert "High Value Parameters" in html
    assert "Medium Value Parameters" in html
    assert "Low Value Parameters" in html
    assert "Discovered" in html
    assert "Candidate" in html
    assert "../screenshots/www.example.com.png" in html
    assert "screenshots\\www.example.com.png" not in html
    assert "Estimated Requests Attempted" in html
    assert "HTTP Responses Recorded" in html
    assert "12.34s" in html
    assert "Performance Analytics" in html
    assert "Top Slowest Modules" in html
    assert "Top RAM Consumers" in html
    assert "Module Performance" in html
    assert "88.5 MB" in html
    assert "Estimated Requests Attempted" in html
    assert "<td>Probe</td>" in html
    md = (target / "reports" / "report.md").read_text(encoding="utf-8")
    assert "- Scan duration: 12.34s" in md
    assert "## Performance Analytics" in md
    assert "- Peak RAM Usage: 88.5 MB" in md
    assert "- Estimated Requests Attempted: 3" in md
    assert "- HTTP Responses Recorded: 2" in md
    assert "### Top Slowest Modules" in md
    assert "### Top RAM Consumers" in md
    assert "### Top Priority Assets" in md
    assert "## Top Investigation Targets" in md
    assert "## Top Investigation Campaigns" in md
    assert "API Ecosystem" in md
    assert "Critical Investigation" in md
    assert "Very High" in md
    assert "- Coverage strategy: smart_tags_plus_lightweight_baseline" in md
    assert "| Probe | Completed | 1.25s | 80.0 MB | 70.0 MB |" in md
    assert "| Nginx 1.30.1 | High |" in md
    assert "nginx/1.30.1 | www.example.com |" in md
    assert "![](../screenshots/www.example.com.png)" in md


def test_report_encodes_screenshot_paths_relative_to_report_dir(tmp_path: Path) -> None:
    target = tmp_path / "space.example"
    shot_dir = target / "screenshots"
    shot_dir.mkdir(parents=True)
    (shot_dir / "host with space.png").write_text("fake", encoding="utf-8")

    report.run("space.example", output=tmp_path)

    html = (target / "reports" / "report.html").read_text(encoding="utf-8")
    md = (target / "reports" / "report.md").read_text(encoding="utf-8")
    assert "../screenshots/host%20with%20space.png" in html
    assert "![](../screenshots/host%20with%20space.png)" in md


def test_report_shows_skipped_parameters_from_scan_state(tmp_path: Path) -> None:
    target = tmp_path / "empty.example"
    target.mkdir(parents=True)
    (target / "parameters").mkdir()
    (target / "parameters" / "parameters.txt").write_text("token\nredirect_url\n", encoding="utf-8")
    (target / "scan_state.json").write_text(
        '{"modules":{"parameters":{"status":"skipped","error":"No URL sources available"}},"skipped_modules":["parameters"]}',
        encoding="utf-8",
    )

    report.run("empty.example", output=tmp_path)

    html = (target / "reports" / "report.html").read_text(encoding="utf-8")
    md = (target / "reports" / "report.md").read_text(encoding="utf-8")
    assert "Parameters: <strong>Skipped</strong> (No URL sources available)." in html
    assert "Parameters: Skipped (No URL sources available)" in html
    assert "- Parameters found: Skipped (No URL sources available)" in md
    assert 'parameters: [],' in html
    assert "redirect_url" not in html


def test_report_shows_template_unavailable_nuclei_as_skipped(tmp_path: Path) -> None:
    target = tmp_path / "example.com"
    target.mkdir(parents=True)
    (target / "scan_state.json").write_text(
        json.dumps({"modules": {"nuclei": {"status": "failed", "error": "templates unavailable"}}}),
        encoding="utf-8",
    )

    report.run("example.com", output=tmp_path)

    md = (target / "reports" / "report.md").read_text(encoding="utf-8")
    assert "- Vulnerabilities (nuclei findings): Skipped (templates unavailable)" in md
