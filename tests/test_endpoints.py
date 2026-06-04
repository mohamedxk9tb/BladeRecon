import json
from pathlib import Path

from bladerecon.modules.endpoints import _extract_endpoint_items, _extract_endpoints, run


def test_extract_endpoints_normalizes_relative_routes_and_deduplicates() -> None:
    content = """
    fetch('/api/users')
    const graph = "/graphql";
    const absolute = "https://api.example.com/v1/login";
    fetch('/api/users')
    """

    assert set(_extract_endpoints(content, "https://www.example.com/static/app.js")) == {
        "https://www.example.com/api/users",
        "https://api.example.com/v1/login",
        "https://www.example.com/graphql",
    }


def test_extract_endpoints_detects_modern_javascript_patterns() -> None:
    content = """
    fetch(`${base}/api/v2/accounts`)
    axios.post('/auth/login')
    xhr.open('GET', '/swagger.json')
    const client = new WebSocket('wss://stream.example.com/socket.io/?token=x')
    const apollo = { uri: '/graphql/' }
    const docs = "/api-docs";
    """

    items = _extract_endpoint_items(content, "https://www.example.com/assets/main.js")
    endpoints = {item["endpoint"]: item["category"] for item in items}

    assert "https://www.example.com/api/v2/accounts" in endpoints
    assert endpoints["https://www.example.com/auth/login"] == "REST"
    assert endpoints["https://www.example.com/swagger.json"] == "Swagger/OpenAPI"
    assert endpoints["wss://stream.example.com/socket.io/?token=x"] == "WebSocket"
    assert endpoints["https://www.example.com/graphql/"] == "GraphQL"
    assert endpoints["https://www.example.com/api-docs"] == "Swagger/OpenAPI"


def test_extract_endpoints_detects_bundle_route_properties_without_leading_slash() -> None:
    content = """
    const api = axios.create({ baseURL: "api/internal" });
    const routes = [
      { path: "v3/orders" },
      { url: "auth/session" },
      { endpoint: `graphql` },
      { route: "/admin/users" }
    ];
    api.get("v2/profile")
    """

    endpoints = set(_extract_endpoints(content, "https://app.example.com/assets/bundle.js"))

    assert "https://app.example.com/api/internal" in endpoints
    assert "https://app.example.com/v3/orders" in endpoints
    assert "https://app.example.com/auth/session" in endpoints
    assert "https://app.example.com/graphql" in endpoints
    assert "https://app.example.com/admin/users" in endpoints
    assert "https://app.example.com/v2/profile" in endpoints


def test_endpoint_run_keeps_source_file_attribution(tmp_path: Path) -> None:
    target = tmp_path / "example.com"
    js_dir = target / "js" / "files"
    js_dir.mkdir(parents=True)
    (js_dir / "app.js").write_text("fetch('/api/users')", encoding="utf-8")
    (target / "js" / "js_files.json").write_text(
        '[{"url":"https://www.example.com/app.js","source_page":"https://www.example.com","local_path":"js/files/app.js"}]',
        encoding="utf-8",
    )

    rows = run("example.com", output=tmp_path)

    assert rows == [
        {
            "endpoint": "https://www.example.com/api/users",
            "source": "https://www.example.com/app.js",
            "source_js_file": "app.js",
            "category": "REST",
        }
    ]


def test_endpoint_run_suppresses_third_party_api_noise(tmp_path: Path) -> None:
    target = tmp_path / "example.com"
    js_dir = target / "js" / "files"
    js_dir.mkdir(parents=True)
    (js_dir / "app.js").write_text(
        """
        fetch("https://cdn.vendor.test/api/telemetry")
        fetch("https://api.example.com/v1/users")
        """,
        encoding="utf-8",
    )
    (target / "js" / "js_files.json").write_text(
        json.dumps(
            [
                {
                    "url": "https://www.example.com/app.js",
                    "source_page": "https://www.example.com",
                    "local_path": "js/files/app.js",
                }
            ]
        ),
        encoding="utf-8",
    )

    rows = run("example.com", output=tmp_path)
    metadata = json.loads((target / "endpoints" / "metadata.json").read_text(encoding="utf-8"))

    assert [row["endpoint"] for row in rows] == ["https://api.example.com/v1/users"]
    assert metadata["parsed_js_files"] == 1
    assert metadata["suppressed"]["third_party_endpoint_from_in_scope_js"] == 1


def test_endpoint_run_consumes_historical_js_endpoint_artifacts(tmp_path: Path) -> None:
    target = tmp_path / "example.com"
    (target / "js").mkdir(parents=True)
    (target / "js" / "js_files.json").write_text("[]", encoding="utf-8")
    historical = target / "historical_js"
    historical.mkdir()
    (historical / "endpoints.json").write_text(
        json.dumps(
            [
                {"endpoint": "https://support.example.com/api/tickets", "source": "https://support.example.com/app.js"},
                {"endpoint": "https://cdn.vendor.test/api/noise", "source": "https://cdn.vendor.test/app.js"},
            ]
        ),
        encoding="utf-8",
    )

    rows = run("example.com", output=tmp_path)
    metadata = json.loads((target / "endpoints" / "metadata.json").read_text(encoding="utf-8"))

    assert rows == [
        {
            "endpoint": "https://support.example.com/api/tickets",
            "source": "https://support.example.com/app.js",
            "source_js_file": "historical_js",
            "category": "REST",
        }
    ]
    assert metadata["historical_js_endpoint_rows"] == 2
    assert metadata["suppressed"]["third_party_endpoint_from_third_party_js"] == 1
