import json

import subprocess
import sys
from pathlib import Path

import pytest

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


def test_nuclei_process_timeout_removes_temp_files(tmp_path):
    cmd = [sys.executable, "-c", "import time; time.sleep(5)"]

    with pytest.raises(subprocess.TimeoutExpired):
        nuclei._run_nuclei_process(cmd, timeout=1, out_dir=tmp_path, template_total=None, target_count=1, enforce_timeout=True, progress_interval=1)

    assert not (tmp_path / "stdout.tmp").exists()
    assert not (tmp_path / "stderr.tmp").exists()


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


def test_nuclei_baseline_skips_when_target_count_exceeds_ceiling():
    needed, reason = nuclei._baseline_practicality(
        enabled=True,
        selected_tags=["php"],
        explicit_templates=False,
        baseline_target_count=250,
        max_targets=50,
    )

    assert needed is False
    assert "exceeds baseline safety ceiling" in reason


def test_nuclei_uses_baseline_only_when_opportunity_evidence_exists(tmp_path, monkeypatch):
    target = tmp_path / "example.com"
    alive = target / "probe" / "alive.txt"
    alive.parent.mkdir(parents=True)
    alive.write_text("https://www.example.com\n", encoding="utf-8")
    (target / "intelligence").mkdir()
    (target / "intelligence" / "template_intelligence.json").write_text('{"selected_tags":[]}', encoding="utf-8")
    (target / "intelligence" / "opportunity_priorities.json").write_text(
        json.dumps([{"target": "https://www.example.com/admin", "score": 82, "confidence": "High"}]),
        encoding="utf-8",
    )
    captured = {}

    monkeypatch.setattr(nuclei, "_nuclei_exists", lambda: True)
    monkeypatch.setattr(nuclei, "nuclei_template_status", lambda *args, **kwargs: {"ok": True, "path": str(tmp_path)})

    def fake_run(cmd, timeout, out_dir, template_total, target_count, enforce_timeout=False, progress_interval=10):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, "", "[INF] Templates loaded for current scan: 12")

    monkeypatch.setattr(nuclei, "_run_nuclei_process", fake_run)

    result = nuclei.run(domain="example.com", output=tmp_path)

    assert result.status == "completed"
    assert "-as" not in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("-severity") + 1] == "critical,high"
    assert captured["cmd"][captured["cmd"].index("-tags") + 1] == "cve,exposure,misconfig"
    metadata = json.loads((target / "nuclei" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["baseline_only"] is True
    assert metadata["coverage_strategy"] == "baseline_only"


def test_nuclei_baseline_only_scopes_to_validated_opportunity_hosts(tmp_path, monkeypatch):
    target = tmp_path / "example.com"
    alive = target / "probe" / "alive.txt"
    alive.parent.mkdir(parents=True)
    alive.write_text(
        "https://api.example.com\nhttps://static.example.com\nhttps://admin.example.com\n",
        encoding="utf-8",
    )
    (target / "intelligence").mkdir()
    (target / "intelligence" / "template_intelligence.json").write_text('{"selected_tags":[]}', encoding="utf-8")
    (target / "intelligence" / "opportunity_priorities.json").write_text(
        json.dumps(
            [
                {
                    "target": "https://api.example.com/graphql",
                    "score": 92,
                    "confidence": "High",
                    "validation_strength": "Strong",
                    "positive_validation_signals": ["GraphQL path returned actionable response"],
                },
                {
                    "target": "https://static.example.com/old",
                    "score": 60,
                    "confidence": "Medium",
                    "validation_strength": "Weak",
                    "opportunity_type": "Historical",
                },
            ]
        ),
        encoding="utf-8",
    )
    captured = {}

    monkeypatch.setattr(nuclei, "_nuclei_exists", lambda: True)
    monkeypatch.setattr(nuclei, "nuclei_template_status", lambda *args, **kwargs: {"ok": True, "path": str(tmp_path)})

    def fake_run(cmd, timeout, out_dir, template_total, target_count, enforce_timeout=False, progress_interval=10):
        captured["cmd"] = cmd
        captured["target_count"] = target_count
        return subprocess.CompletedProcess(cmd, 0, "", "[INF] Templates loaded for current scan: 12")

    monkeypatch.setattr(nuclei, "_run_nuclei_process", fake_run)

    result = nuclei.run(domain="example.com", output=tmp_path)

    assert result.status == "completed"
    scoped_file = captured["cmd"][captured["cmd"].index("-l") + 1]
    assert Path(scoped_file).name == "opportunity_targets.txt"
    assert Path(scoped_file).read_text(encoding="utf-8").strip() == "https://api.example.com"
    assert captured["target_count"] == 1
    metadata = json.loads((target / "nuclei" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["target_scope"]["enabled"] is True
    assert metadata["target_scope"]["reason"] == "opportunity ROI target scope"
    assert metadata["targets_count"] == 1


def test_nuclei_baseline_only_skips_when_roi_hosts_are_not_current_targets(tmp_path, monkeypatch):
    target = tmp_path / "example.com"
    alive = target / "probe" / "alive.txt"
    alive.parent.mkdir(parents=True)
    alive.write_text("https://www.example.com\n", encoding="utf-8")
    (target / "intelligence").mkdir()
    (target / "intelligence" / "template_intelligence.json").write_text('{"selected_tags":[]}', encoding="utf-8")
    (target / "intelligence" / "opportunity_priorities.json").write_text(
        json.dumps(
            [
                {
                    "target": "https://api.example.com/graphql",
                    "score": 92,
                    "confidence": "High",
                    "validation_strength": "Strong",
                }
            ]
        ),
        encoding="utf-8",
    )
    executed = {"value": False}

    monkeypatch.setattr(nuclei, "_nuclei_exists", lambda: True)
    monkeypatch.setattr(nuclei, "nuclei_template_status", lambda *args, **kwargs: {"ok": True, "path": str(tmp_path)})

    def fake_run(*args, **kwargs):
        executed["value"] = True
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(nuclei, "_run_nuclei_process", fake_run)

    result = nuclei.run(domain="example.com", output=tmp_path)

    assert result.status == "skipped"
    assert executed["value"] is False
    metadata = json.loads((target / "nuclei" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["target_scope"]["scoped_targets"] == 0
    assert "not present" in metadata["skip_reason"]


def test_nuclei_skips_smart_baseline_when_scoped_scan_covers_roi_hosts(tmp_path, monkeypatch):
    target = tmp_path / "example.com"
    alive = target / "probe" / "alive.txt"
    alive.parent.mkdir(parents=True)
    alive.write_text("https://api.example.com\nhttps://www.example.com\n", encoding="utf-8")
    tech = target / "technology" / "technology.json"
    tech.parent.mkdir()
    tech.write_text(json.dumps([{"name": "Nginx", "hosts": ["api.example.com"], "confidence": "High"}]), encoding="utf-8")
    (target / "intelligence").mkdir()
    (target / "intelligence" / "template_intelligence.json").write_text('{"selected_tags":["nginx"]}', encoding="utf-8")
    (target / "intelligence" / "opportunity_priorities.json").write_text(
        json.dumps([{"target": "https://api.example.com/admin", "score": 90, "confidence": "High", "validation_strength": "Strong"}]),
        encoding="utf-8",
    )
    calls = []

    monkeypatch.setattr(nuclei, "_nuclei_exists", lambda: True)
    monkeypatch.setattr(nuclei, "nuclei_template_status", lambda *args, **kwargs: {"ok": True, "path": str(tmp_path)})

    def fake_run(cmd, timeout, out_dir, template_total, target_count, enforce_timeout=False, progress_interval=10):
        calls.append({"cmd": cmd, "target_count": target_count})
        return subprocess.CompletedProcess(cmd, 0, "", "[INF] Templates loaded for current scan: 4")

    monkeypatch.setattr(nuclei, "_run_nuclei_process", fake_run)

    result = nuclei.run(domain="example.com", output=tmp_path)

    assert result.status == "completed"
    assert len(calls) == 1
    metadata = json.loads((target / "nuclei" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["baseline_scan"]["applied"] is False
    assert "already covers" in metadata["baseline_scan"]["reason"]


def test_nuclei_smart_baseline_scopes_to_uncovered_roi_hosts(tmp_path, monkeypatch):
    target = tmp_path / "example.com"
    alive = target / "probe" / "alive.txt"
    alive.parent.mkdir(parents=True)
    alive.write_text("https://api.example.com\nhttps://www.example.com\n", encoding="utf-8")
    tech = target / "technology" / "technology.json"
    tech.parent.mkdir()
    tech.write_text(json.dumps([{"name": "Nginx", "hosts": ["www.example.com"], "confidence": "High"}]), encoding="utf-8")
    (target / "intelligence").mkdir()
    (target / "intelligence" / "template_intelligence.json").write_text('{"selected_tags":["nginx"]}', encoding="utf-8")
    (target / "intelligence" / "opportunity_priorities.json").write_text(
        json.dumps([{"target": "https://api.example.com/admin", "score": 90, "confidence": "High", "validation_strength": "Strong"}]),
        encoding="utf-8",
    )
    calls = []

    monkeypatch.setattr(nuclei, "_nuclei_exists", lambda: True)
    monkeypatch.setattr(nuclei, "nuclei_template_status", lambda *args, **kwargs: {"ok": True, "path": str(tmp_path)})

    def fake_run(cmd, timeout, out_dir, template_total, target_count, enforce_timeout=False, progress_interval=10):
        calls.append({"cmd": cmd, "target_count": target_count})
        return subprocess.CompletedProcess(cmd, 0, "", "[INF] Templates loaded for current scan: 4")

    monkeypatch.setattr(nuclei, "_run_nuclei_process", fake_run)

    result = nuclei.run(domain="example.com", output=tmp_path)

    assert result.status == "completed"
    assert len(calls) == 2
    baseline_cmd = calls[1]["cmd"]
    baseline_file = Path(baseline_cmd[baseline_cmd.index("-l") + 1])
    assert baseline_file.name == "baseline_opportunity_targets.txt"
    assert baseline_file.read_text(encoding="utf-8").strip() == "https://api.example.com"
    metadata = json.loads((target / "nuclei" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["baseline_scan"]["applied"] is True
    assert metadata["baseline_scan"]["targets_count"] == 1
    assert metadata["baseline_scan"]["roi"]["gap_hosts"] == ["api.example.com"]


def test_nuclei_skips_baseline_only_without_opportunity_evidence(tmp_path, monkeypatch):
    target = tmp_path / "example.com"
    alive = target / "probe" / "alive.txt"
    alive.parent.mkdir(parents=True)
    alive.write_text("https://www.example.com\n", encoding="utf-8")
    (target / "intelligence").mkdir()
    (target / "intelligence" / "template_intelligence.json").write_text('{"selected_tags":[]}', encoding="utf-8")
    executed = {"value": False}

    monkeypatch.setattr(nuclei, "_nuclei_exists", lambda: True)
    monkeypatch.setattr(nuclei, "nuclei_template_status", lambda *args, **kwargs: {"ok": True, "path": str(tmp_path)})

    def fake_run(*args, **kwargs):
        executed["value"] = True
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(nuclei, "_run_nuclei_process", fake_run)

    result = nuclei.run(domain="example.com", output=tmp_path)

    assert result.status == "skipped"
    assert executed["value"] is False
    metadata = json.loads((target / "nuclei" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "skipped"
    assert metadata["coverage_strategy"] == "skipped_low_roi_baseline"
    assert metadata["roi_decision"]["run"] is False
    assert (target / "nuclei" / "results.json").read_text(encoding="utf-8").strip() == "[]"


def test_nuclei_roi_requires_high_confidence_not_score_only(tmp_path):
    target = tmp_path / "example.com" / "intelligence"
    target.mkdir(parents=True)
    (target / "opportunity_priorities.json").write_text(
        json.dumps([{"target": "https://api.example.com", "score": 95, "confidence": "Medium"}]),
        encoding="utf-8",
    )

    decision = nuclei._nuclei_roi_decision(
        tmp_path,
        "example.com",
        baseline_only=True,
        selected_tags=[],
        explicit_templates=False,
        automatic_scan=False,
    )

    assert decision["run"] is False


def test_nuclei_roi_ignores_weak_legacy_only_validation(tmp_path):
    target = tmp_path / "example.com" / "intelligence"
    target.mkdir(parents=True)
    (target / "opportunity_priorities.json").write_text(
        json.dumps(
            [
                {
                    "target": "https://api.example.com/old",
                    "score": 70,
                    "confidence": "Medium",
                    "validation_strength": "Weak",
                    "validation_score": 1,
                    "positive_validation_signals": ["No modern equivalent or legacy path detected"],
                }
            ]
        ),
        encoding="utf-8",
    )

    decision = nuclei._nuclei_roi_decision(
        tmp_path,
        "example.com",
        baseline_only=True,
        selected_tags=[],
        explicit_templates=False,
        automatic_scan=False,
    )

    assert decision["run"] is False


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
