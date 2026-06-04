import json
from pathlib import Path

from bladerecon.modules.js import _extract_script_urls, _load_historical_js_candidates, _prioritize_alive_hosts


def test_extract_script_urls_resolves_relative_and_deduplicates() -> None:
    html = """
    <script src="/static/app.js"></script>
    <script src="chunk.js"></script>
    <script src="/static/app.js"></script>
    <script src="data:text/javascript,alert(1)"></script>
    """

    assert _extract_script_urls(html, "https://example.com/app/") == [
        "https://example.com/static/app.js",
        "https://example.com/app/chunk.js",
    ]


def test_prioritize_alive_hosts_prefers_real_pages_over_404s() -> None:
    alive = [
        "https://missing.example.com",
        "https://store.example.com",
        "https://other.example.com",
    ]
    probe_rows = [
        {"url": "https://missing.example.com", "status_code": 404, "title": "Not Found", "content_length": 200},
        {"final_url": "https://store.example.com/", "status_code": 200, "title": "Storefront", "content_length": 5000},
        {"url": "https://other.example.com", "status_code": 403, "title": "Forbidden", "content_length": 100},
    ]

    assert _prioritize_alive_hosts(alive, probe_rows, "example.com", 1) == ["https://store.example.com"]


def test_load_historical_js_candidates_reuses_existing_artifact(tmp_path: Path) -> None:
    historical = tmp_path / "historical_js"
    historical.mkdir()
    (historical / "js_urls.json").write_text(
        json.dumps([{"url": "https://cdn.example.com/app.js"}, {"url": "https://cdn.example.com/app.js"}]),
        encoding="utf-8",
    )

    assert _load_historical_js_candidates(tmp_path) == ["https://cdn.example.com/app.js"]
