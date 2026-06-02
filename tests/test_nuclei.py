import json

from bladerecon.modules import nuclei


def test_nuclei_writes_json_array_and_jsonl(tmp_path):
    jsonl = "\n".join(
        [
            '{"template":"exposure","host":"https://example.com","info":{"name":"Exposure","severity":"medium"}}',
            "",
        ]
    )

    nuclei._write_results(tmp_path, jsonl)

    data = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert data[0]["template"] == "exposure"
    assert (tmp_path / "results.jsonl").read_text(encoding="utf-8") == jsonl
    assert "Total findings: 1" in (tmp_path / "results.md").read_text(encoding="utf-8")


def test_nuclei_uses_empty_alive_file_as_empty_target_list(tmp_path):
    alive = tmp_path / "example.com" / "probe" / "alive.txt"
    alive.parent.mkdir(parents=True)
    alive.write_text("", encoding="utf-8")

    target_domain, target_list, target_name = nuclei._resolve_target_file("example.com", None, tmp_path)

    assert target_domain is None
    assert target_list == alive
    assert target_name == "example.com"


def test_nuclei_loads_detected_technologies(tmp_path):
    tech_path = tmp_path / "example.com" / "technologies" / "technologies.json"
    tech_path.parent.mkdir(parents=True)
    tech_path.write_text(json.dumps([{"detected": ["PHP", "Apache", "PHP"]}]), encoding="utf-8")

    assert nuclei._load_detected_technologies(tmp_path, "example.com") == ["Apache", "PHP"]


def test_nuclei_detects_tag_filter_template_miss():
    stderr = "could not find any templates with tech tag: drupal,java,nextjs"

    assert nuclei._no_templates_for_filters(stderr)


def test_nuclei_removes_tag_filter_without_touching_other_flags():
    cmd = ["nuclei", "-u", "https://example.com", "-tags", "drupal,nextjs", "-as", "-j"]

    assert nuclei._remove_flag_with_value(cmd, "-tags") == ["nuclei", "-u", "https://example.com", "-as", "-j"]


def test_nuclei_baseline_command_removes_tags_and_restores_original_targets(tmp_path):
    alive = tmp_path / "alive.txt"
    alive.write_text("https://www.example.com\n", encoding="utf-8")
    scoped = tmp_path / "scoped.txt"
    scoped.write_text("https://php.example.com\n", encoding="utf-8")
    cmd = ["nuclei", "-l", str(scoped), "-severity", "critical,high,medium", "-tags", "php", "-j"]

    baseline = nuclei._baseline_target_command(cmd, None, alive)
    baseline = nuclei._replace_flag_value(baseline, "-severity", "critical,high")

    assert "-tags" not in baseline
    assert baseline[baseline.index("-l") + 1] == str(alive)
    assert baseline[baseline.index("-severity") + 1] == "critical,high"


def test_nuclei_normalizes_bom_target_lists(tmp_path):
    target_list = tmp_path / "targets.txt"
    target_list.write_text("\ufeffhttp://127.0.0.1:8765\n", encoding="utf-8")

    normalized = nuclei._normalize_target_list_file(target_list, tmp_path)

    assert normalized.read_bytes().startswith(b"http://127.0.0.1")


def test_nuclei_scopes_intelligence_tags_to_matching_hosts(tmp_path):
    target = tmp_path / "example.com"
    alive = target / "probe" / "alive.txt"
    alive.parent.mkdir(parents=True)
    alive.write_text("https://php.example.com\nhttps://static.example.com\n", encoding="utf-8")
    tech = target / "technology" / "technology.json"
    tech.parent.mkdir(parents=True)
    tech.write_text(
        json.dumps([{"name": "PHP", "hosts": ["php.example.com"], "confidence": "High"}]),
        encoding="utf-8",
    )
    out_dir = target / "nuclei"
    out_dir.mkdir()

    scope = nuclei._scope_target_list(alive, tmp_path, "example.com", out_dir, ["php"], explicit_list=False)

    assert scope["enabled"] is True
    assert scope["original_targets"] == 2
    assert scope["scoped_targets"] == 1
    assert (out_dir / "scoped_targets.txt").read_text(encoding="utf-8").strip() == "https://php.example.com"


def test_nuclei_banner_filter_preserves_warnings_errors_and_stats():
    raw = "\n".join(
        [
            "                     __     _",
            "[INF] Current nuclei version: v3.8.0",
            "[INF] ProjectDiscovery templates loaded",
            "[INF] Templates loaded for current scan: 42",
            "[WRN] rate limit reached",
            "[ERR] could not connect",
        ]
    )

    cleaned = nuclei._clean_nuclei_output(raw)

    assert "Current nuclei version" not in cleaned
    assert "ProjectDiscovery" not in cleaned
    assert "Templates loaded for current scan: 42" in cleaned
    assert "[WRN] rate limit reached" in cleaned
    assert "[ERR] could not connect" in cleaned
