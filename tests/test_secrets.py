import json
from pathlib import Path

from bladerecon.modules.secrets import _find_secrets, run


def test_find_secrets_detects_common_javascript_patterns() -> None:
    content = """
    const google = "AIzaSyD-abcdefghijklmnopqrstuvwxyz01234";
    const token = "Bearer abcdefghijklmnopqrstuvwxyz123456";
    """

    findings = _find_secrets(content)
    types = {item["type"] for item in findings}

    assert "Google API Key" in types
    assert "Bearer Token" in types
    by_type = {item["type"]: item for item in findings}
    assert by_type["Google API Key"]["confidence"] == "LOW"
    assert by_type["Bearer Token"]["confidence"] == "MEDIUM"
    assert by_type["Bearer Token"]["risk"] == "Medium"
    assert "value_preview" in by_type["Google API Key"]


def test_secret_run_consumes_historical_js_secret_artifacts(tmp_path: Path) -> None:
    target = tmp_path / "example.com"
    (target / "js").mkdir(parents=True)
    (target / "js" / "js_files.json").write_text("[]", encoding="utf-8")
    historical = target / "historical_js"
    historical.mkdir()
    (historical / "secrets.json").write_text(
        json.dumps(
            [
                {
                    "type": "Google API Key",
                    "value": "AIzaSyD-abcdefghijklmnopqrstuvwxyz01234",
                    "value_preview": "AIzaSyD-...01234",
                    "confidence": "HIGH",
                    "risk": "High",
                    "source": "https://static.example.com/app.js",
                }
            ]
        ),
        encoding="utf-8",
    )

    rows = run("example.com", output=tmp_path)
    metadata = json.loads((target / "secrets" / "metadata.json").read_text(encoding="utf-8"))

    assert rows == [
        {
            "type": "Google API Key",
            "value": "AIzaSyD-abcdefghijklmnopqrstuvwxyz01234",
            "value_preview": "AIzaSyD-...01234",
            "confidence": "HIGH",
            "risk": "High",
            "source": "https://static.example.com/app.js",
            "source_type": "historical_js",
        }
    ]
    assert metadata["historical_js_secret_rows"] == 1
