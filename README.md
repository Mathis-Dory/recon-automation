# Pentest Recon Automation Suite

Python CLI tools for authorized lab/redteam recon. See
`docs/specs/2026-06-19-pentest-recon-automation-design.md`.

Tools (symlinked into `../../go-tools/bin/` with a `pt-` prefix):
- `pt-enum`   — service enumeration + web fingerprint → Excel
- `pt-nessus` — launch a Nessus scan via the REST API
- `pt-nuclei` — run nuclei → JSONL
- `pt-smb`    — netexec SMB mass-recon → Excel
- `pt-sweep`  — live-host discovery → hosts file
- `pt-recon`  — orchestrate the above

Secrets: `~/.config/pentest-recon/config.ini` (mode 0600). Authorized use only.
