# Pentest Recon Automation Suite

Python CLI tools for authorized lab/redteam recon. Architecture documented
under [`docs/specs/`](docs/specs/); implementation plans under
[`docs/plans/`](docs/plans/).

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

Probe families currently exposed by the `enum` stage:

- **Built-in**: probe-ftp, probe-ssh, probe-web-basic, probe-smb (null/guest)
- **DB banners**: probe-db (MySQL / Postgres / MSSQL / Mongo / Redis)
- **Mail**: probe-mail (SMTP / IMAP / POP3 banner + STARTTLS / AUTH)
- **Web depth**: probe-web-deep (server / X-Powered-By / robots / favicon hash)
  and probe-tls-cert (subject / SAN / issuer / expiry)
- **AD / Windows** (via `nxc`, soft-required): probe-ldap, probe-rdp, probe-winrm,
  probe-smb-signing (relay eligibility), probe-smb-passpol, probe-smb-rid (anon)
- **NFS**: probe-nfs (`showmount -e`, soft-required)

Each probe is independently toggleable via `--no-probe-<name>`; the whole
enum stage is skippable via `--no-enum`. See `pt-recon --list-modules` for
the live set.

Operator flags worth knowing: `--scope-file <path>` (allow-list of CIDRs),
`--outdir <path>` / `$PT_RECON_OUTPUT` (engagement dir root), `--concurrency N`
(probe thread pool size, default 32), `--resume` (skip stages whose run.json
record is `status=ok` and whose artifact is on disk). Meta subcommands:
`pt-recon status NAME` and `pt-recon diff NAME_A NAME_B`.

Secrets: `~/.config/pentest-recon/config.ini` (mode 0600). Authorized use only.
