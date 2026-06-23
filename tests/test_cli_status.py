import json

from recon import cli_status


def _seed_engagement(outdir, name="acme"):
    outdir.mkdir()
    (outdir / "run.json").write_text(
        json.dumps(
            {
                "engagement": name,
                "started_at": "2026-06-23T10:00:00Z",
                "finished_at": "2026-06-23T10:05:00Z",
                "targets": {"count": 5, "source": "-r 10.0.0.0/30"},
                "stages": [
                    {
                        "name": "sweep",
                        "status": "ok",
                        "elapsed_s": 1.5,
                        "modules_run": ["sweep"],
                        "modules_skipped": [],
                        "exit_code": 0,
                    },
                    {
                        "name": "nessus",
                        "status": "skipped",
                        "elapsed_s": 0.0,
                        "modules_run": [],
                        "modules_skipped": [
                            {
                                "name": "nessus",
                                "reason": "config nessus.access_key missing or empty",
                            }
                        ],
                        "exit_code": None,
                    },
                ],
                "exit_code": 0,
            }
        )
    )
    (outdir / "live-hosts.txt").write_text("10.0.0.1\n10.0.0.2\n")
    (outdir / "nuclei.jsonl").write_text(
        '{"host": "10.0.0.1", "template-id": "ssh-banner", "info": {"severity": "info"}}\n'
    )


def test_status_prints_engagement_summary(tmp_path, monkeypatch, capsys):
    outdir = tmp_path / "acme"
    _seed_engagement(outdir)
    monkeypatch.setattr("recon.common.engagement_dir", lambda name, root=None: str(outdir))
    rc = cli_status.main(["acme"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "engagement: acme" in out
    assert "sweep" in out
    assert "skipped" in out
    assert "10.0.0.0/30" in out
    assert "live-hosts.txt" in out
    assert "2 hosts" in out
    assert "1 findings" in out


def test_status_missing_run_json_returns_1(tmp_path, monkeypatch, capsys):
    outdir = tmp_path / "nope"
    outdir.mkdir()
    monkeypatch.setattr("recon.common.engagement_dir", lambda name, root=None: str(outdir))
    rc = cli_status.main(["nope"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "no run.json" in err


def test_status_honors_outdir_arg(tmp_path, monkeypatch, capsys):
    outdir = tmp_path / "vault" / "acme"
    outdir.parent.mkdir()
    _seed_engagement(outdir)
    # Don't monkeypatch engagement_dir — let the real one resolve via --outdir.
    rc = cli_status.main(["acme", "--outdir", str(tmp_path / "vault")])
    assert rc == 0
    assert "engagement: acme" in capsys.readouterr().out
