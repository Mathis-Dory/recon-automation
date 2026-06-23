# Pentest Recon Automation Suite

Python CLI tools for authorized lab/redteam recon. See
`docs/specs/2026-06-19-pentest-recon-automation-design.md`.

Tool: `pt-recon` — registry-driven recon orchestrator. All stages are
default-on (auto-skip if their prerequisites are missing).

Stages are exposed as subcommands for ad-hoc per-stage use:
- `pt-recon sweep`  — live-host discovery → hosts file
- `pt-recon enum`   — service enumeration + web fingerprint → Excel
- `pt-recon nuclei` — run nuclei → JSONL
- `pt-recon nessus` — launch a Nessus scan via the REST API
- `pt-recon smb`    — netexec SMB mass-recon → Excel

Run `pt-recon --list-modules` to inspect the registry; `pt-recon --dry-run`
shows what would run for the current target set.

Secrets: `~/.config/pentest-recon/config.ini` (mode 0600). Authorized use only.
