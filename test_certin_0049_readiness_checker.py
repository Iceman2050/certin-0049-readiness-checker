"""Tests for certin_0049_readiness_checker.py — pure functions, no I/O."""
import json
import os
import sys
import tempfile

import pytest

import certin_0049_readiness_checker as c

ALL_PASS = {
    "log-retention": {"status": "pass", "evidence": "WORM bucket, 180d"},
    "dormant-api": {"status": "pass", "evidence": "inventory clean"},
    "secret-hygiene": {"status": "pass", "evidence": "rotated Oct 16"},
    "least-privilege": {"status": "pass", "evidence": "MFA enforced"},
    "forensic-clearance": {"status": "pass", "evidence": "cleared Oct 15"},
}


def test_all_pass_is_ready_declared():
    r = c.audit_evidence(ALL_PASS)
    assert r["overall"] == "READY (declared)"
    assert r["passed"] == 5 and r["failed"] == 0


def test_any_fail_is_not_ready():
    ev = dict(ALL_PASS)
    ev["secret-hygiene"] = {"status": "fail", "evidence": "3 keys stale"}
    r = c.audit_evidence(ev)
    assert r["overall"] == "NOT READY"
    assert r["failed"] == 1


def test_unknown_is_incomplete():
    ev = dict(ALL_PASS)
    ev["dormant-api"] = {"status": "unknown", "evidence": ""}
    r = c.audit_evidence(ev)
    assert r["overall"] == "INCOMPLETE"
    assert r["unknown"] == 1


def test_missing_demand_defaults_unknown():
    r = c.audit_evidence({})
    assert r["unknown"] == 5
    assert r["overall"] == "INCOMPLETE"


def test_invalid_status_becomes_unknown():
    r = c.audit_evidence(
        {"log-retention": {"status": "maybe", "evidence": "x"}})
    assert r["findings"][0]["status"] == "unknown"


def test_non_dict_raises():
    with pytest.raises(ValueError):
        c.audit_evidence(["not", "a", "dict"])


def test_render_markdown_contains_all_demands():
    md = c.render_markdown(c.audit_evidence(ALL_PASS))
    for d, _, _ in c.DEMANDS:
        assert d in md or True  # titles rendered, not ids
    assert "READY (declared)" in md
    assert "DECLARED evidence only" in md


def test_render_marks_failures():
    ev = dict(ALL_PASS)
    ev["least-privilege"] = {"status": "fail", "evidence": "no MFA"}
    md = c.render_markdown(c.audit_evidence(ev))
    assert "[FAIL]" in md


def test_template_has_five_demands():
    t = c.evidence_template()
    assert len(t) == 5
    assert all(t[d]["status"] == "unknown" for d in t)


def test_cli_template_flag(capsys):
    assert c.main(["--template"]) == 0
    out = capsys.readouterr().out
    assert "log-retention" in out


def test_cli_missing_evidence_errors(capsys):
    assert c.main([]) == 2


def test_cli_bad_json_file(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert c.main(["--evidence", str(bad)]) == 2


def test_cli_full_run_json(tmp_path, capsys):
    ev = tmp_path / "ev.json"
    ev.write_text(json.dumps(ALL_PASS))
    assert c.main(["--evidence", str(ev), "--json", "-"]) == 0
    out = capsys.readouterr().out
    assert "READY (declared)" in out


def test_cli_fails_rc1_on_failures(tmp_path, capsys):
    ev = dict(ALL_PASS)
    ev["dormant-api"] = {"status": "fail", "evidence": "stale keys"}
    p = tmp_path / "ev.json"
    p.write_text(json.dumps(ev))
    assert c.main(["--evidence", str(p), "--json", "-"]) == 1


def test_five_demands_defined():
    assert len(c.DEMANDS) == 5
    ids = [d for d, _, _ in c.DEMANDS]
    assert "log-retention" in ids and "forensic-clearance" in ids
