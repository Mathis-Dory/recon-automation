"""pt-recon status: summarize a prior engagement run from its run.json."""

import argparse
import json
import os
import sys

from recon import common


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="pt-recon status",
        description="Summarize a prior engagement's run.json and artifacts.",
    )
    parser.add_argument("name", help="engagement name")
    parser.add_argument(
        "--outdir",
        dest="outdir",
        help="engagement output root (overrides $PT_RECON_OUTPUT and default)",
    )
    return parser


def _format_table(rows):
    if not rows:
        return ""
    widths = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*[str(c) for c in rows[0]])]
    lines.append("  ".join("-" * w for w in widths))
    for row in rows[1:]:
        lines.append(fmt.format(*[str(c) for c in row]))
    return "\n".join(lines)


def _human_size(n):
    for unit in ("B", "KB", "MB"):
        if n < 1024 or unit == "MB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} MB"


def _summarize_artifacts(outdir):
    """Return a list of (filename, size_str, detail_str) tuples for artifacts present."""
    lines = []
    for name in ("live-hosts.txt", "enum.xlsx", "nuclei.jsonl", "smb.xlsx"):
        path = os.path.join(outdir, name)
        if not os.path.exists(path):
            continue
        size = _human_size(os.path.getsize(path))
        detail = ""
        if name == "live-hosts.txt":
            with open(path) as fh:
                detail = f"{sum(1 for ln in fh if ln.strip())} hosts"
        elif name == "nuclei.jsonl":
            with open(path) as fh:
                detail = f"{sum(1 for ln in fh if ln.strip())} findings"
        lines.append((name, size, detail))
    return lines


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    outdir = common.engagement_dir(args.name, root=args.outdir)
    run_path = os.path.join(outdir, "run.json")
    if not os.path.exists(run_path):
        print(f"error: no run.json at {run_path}", file=sys.stderr)
        return 1

    with open(run_path) as fh:
        data = json.load(fh)

    print(f"engagement: {data.get('engagement', args.name)}")
    print(f"started:    {data.get('started_at')}")
    print(f"finished:   {data.get('finished_at') or '(in progress / interrupted)'}")
    targets = data.get("targets") or {}
    print(f"targets:    {targets.get('count', '?')} ({targets.get('source', '')})")
    print(f"exit code:  {data.get('exit_code')}")
    print()

    rows = [("stage", "status", "elapsed", "exit", "run", "skipped")]
    for s in data.get("stages", []):
        rows.append(
            (
                s.get("name", "?"),
                s.get("status", "?"),
                f"{s.get('elapsed_s', 0):.1f}s",
                str(s.get("exit_code")),
                ",".join(s.get("modules_run", [])) or "—",
                str(len(s.get("modules_skipped", []))),
            )
        )
    print(_format_table(rows))
    print()

    artifacts = _summarize_artifacts(outdir)
    if artifacts:
        print("artifacts:")
        for name, size, detail in artifacts:
            extra = f" ({detail})" if detail else ""
            print(f"  {name}: {size}{extra}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
