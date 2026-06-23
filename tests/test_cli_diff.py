import json
import os

import pytest

from recon import cli_diff


def _seed(outdir, hosts, nuclei_findings):
    outdir.mkdir(parents=True)
    (outdir / "run.json").write_text(json.dumps({"engagement": outdir.name, "stages": []}))
    (outdir / "live-hosts.txt").write_text("\n".join(hosts) + "\n")
    if nuclei_findings is not None:
        with open(outdir / "nuclei.jsonl", "w") as fh:
            for finding in nuclei_findings:
                fh.write(json.dumps(finding) + "\n")


def test_diff_lists_new_hosts_in_b(tmp_path, monkeypatch, capsys):
    a, b = tmp_path / "a", tmp_path / "b"
    _seed(a, ["10.0.0.1", "10.0.0.2"], [])
    _seed(b, ["10.0.0.1", "10.0.0.2", "10.0.0.5"], [])

    def fake_dir(name, root=None):
        return str({"a": a, "b": b}[name])

    monkeypatch.setattr("recon.common.engagement_dir", fake_dir)
    rc = cli_diff.main(["a", "b"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "+1 new" in out
    assert "10.0.0.5" in out
    assert "10.0.0.1" not in out.split("new hosts:")[-1].split("\n")[0]  # only NEW ones listed


def test_diff_reports_new_nuclei_findings(tmp_path, monkeypatch, capsys):
    a, b = tmp_path / "a", tmp_path / "b"
    _seed(a, ["10.0.0.1"], [
        {"host": "10.0.0.1", "template-id": "ssh-banner",
         "info": {"severity": "info"}, "matched-at": "10.0.0.1:22"},
    ])
    _seed(b, ["10.0.0.1"], [
        {"host": "10.0.0.1", "template-id": "ssh-banner",
         "info": {"severity": "info"}, "matched-at": "10.0.0.1:22"},
        {"host": "10.0.0.1", "template-id": "exposed-panel",
         "info": {"severity": "medium"}, "matched-at": "10.0.0.1:8080/admin"},
    ])

    def fake_dir(name, root=None):
        return str({"a": a, "b": b}[name])

    monkeypatch.setattr("recon.common.engagement_dir", fake_dir)
    cli_diff.main(["a", "b"])
    out = capsys.readouterr().out
    assert "exposed-panel" in out
    assert "ssh-banner" not in out.split("new findings:")[-1]


def test_diff_handles_missing_artifacts_gracefully(tmp_path, monkeypatch, capsys):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    # Both engagement dirs exist but contain nothing.

    def fake_dir(name, root=None):
        return str({"a": a, "b": b}[name])

    monkeypatch.setattr("recon.common.engagement_dir", fake_dir)
    rc = cli_diff.main(["a", "b"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "hosts: 0 → 0" in out


def test_diff_dropped_hosts_shown(tmp_path, monkeypatch, capsys):
    a, b = tmp_path / "a", tmp_path / "b"
    _seed(a, ["10.0.0.1", "10.0.0.2", "10.0.0.3"], [])
    _seed(b, ["10.0.0.1"], [])

    def fake_dir(name, root=None):
        return str({"a": a, "b": b}[name])

    monkeypatch.setattr("recon.common.engagement_dir", fake_dir)
    cli_diff.main(["a", "b"])
    out = capsys.readouterr().out
    assert "no longer responding" in out
    assert "10.0.0.2" in out
    assert "10.0.0.3" in out
