# Recon Modules — Umbrella Design

Date: 2026-06-22
Status: draft, pending user review

## 1. Context

`recon-automation` currently ships six `pt-*` binaries (`pt-sweep`,
`pt-enum`, `pt-nuclei`, `pt-nessus`, `pt-smb`, `pt-recon`) and a small set
of auth-less probes (FTP anon, SSH/Telnet banner, HTTP `<title>`, SMB
null/guest). For lab and red-team recon engagements the operator wants
both **deeper enumeration on the protocols already covered** and **broader
service coverage** — DB banners, mail, LDAP, SNMP, RDP, NFS — together
with a **discovery feedback loop** (cert SANs and other hostname leaks
fed back as new vhosts/targets) and a **consolidated report** that joins
results across stages.

The goal of this umbrella design is to land all of that behind a single,
predictable CLI in stable phases without thrashing the architecture.

## 2. Goals

- One binary, `pt-recon`, with subcommands for ad-hoc per-stage runs.
- "All modules on by default" — operators get the broadest scan that can
  run with their environment; missing prerequisites auto-skip with a
  warning rather than failing the run.
- Two-tier toggles: coarse stage flags (`--no-enum`, `--no-nuclei`, …)
  and fine module flags inside stages (`--no-probe-snmp`, `--no-cert-san`,
  …). Module flags are generated from a registry, not hand-written.
- Cert SAN / PTR / SMB hostname discoveries feed back into a single extra
  pass of the web-touching probes with `Host:` headers.
- One consolidated `report.xlsx` per engagement, joining enum, nuclei,
  smb, and nessus link by `ip:port`.

## 3. Non-goals

- Recursive feedback (single extra pass only — see §8).
- A plugin system with external entry-point discovery (registry stays
  in-process; no extra packaging surface).
- A second renderer for the consolidated report (xlsx only — Markdown or
  HTML can be revisited if there's demand).
- Pulling Nessus scan *results* back into the report — only the scan UI
  link is recorded.
- Authenticated probes (LDAP bind beyond anon, SMB beyond null/guest,
  database creds, etc.) — out of scope.

## 4. Decisions (from brainstorming)

| # | Question                                              | Decision                                                                  |
| - | ----------------------------------------------------- | ------------------------------------------------------------------------- |
| 1 | Module granularity                                    | Two-tier: stage flags + fine module flags inside stages.                  |
| 2 | Binary consolidation                                  | Single `pt-recon`; per-tool binaries removed; subcommands replace them.   |
| 3 | "All on by default" when prerequisites are missing    | Auto-skip with a warning; orchestrator exit 0 if every *attempted* stage succeeded. |
| 4 | Feedback-loop semantics                               | Single extra pass over web modules with `Host:` headers; no recursion.    |
| 5 | Consolidated report format                            | Master `report.xlsx` with sheets for summary / hosts / services / nuclei / smb / nessus-link. |

## 5. Architecture

```
bin/pt-recon ──► recon/cli_recon.py (single entry)
                  │
                  ├─ argparse subparsers: sweep | enum | nuclei | nessus | smb  (ad-hoc per-stage)
                  └─ default (no subcommand): orchestrator over enabled stages
                       │
                       └─ iterates recon/modules.py registry, honoring toggles + prereqs
```

### 5.1 Module registry

`recon/modules.py` exposes:

- A `Module` dataclass: `name: str`, `stage: str`, `run: Callable`,
  `requires: list[Requirement]`, `default_on: bool`, `help: str`.
- A `@module(name=..., stage=..., requires=[...], default_on=True, help="...")`
  decorator that registers the wrapped function on import.
- `iter_modules(stage=None)`, `get_module(name)`, and `register_argparse_flags(parser)`
  helpers.

`Requirement` is a small union: `Tool("nxc")` (binary must be on PATH),
`ConfigKey("nessus", "access_key")` (key must be present and non-empty
in the loaded INI), or `Soft(Tool("showmount"))` (warn once, do not skip
the whole module — the probe itself handles the missing-tool case per
host).

### 5.2 Flag generation

`register_argparse_flags` walks the registry once and adds, for every
module:

- if `default_on=True`: a `--no-<name>` flag (kebab-case from the module
  name);
- if `default_on=False`: a `--<name>` flag.

Today's hand-written `--nessus` / `--smb` opt-in flags are removed (those
modules become `default_on=True`); `--no-nessus` / `--no-smb` replace them.

### 5.3 Stage handlers

Existing `recon/cli_*.py` files stay as stage handlers. The `pt-recon`
subparsers route `pt-recon enum -iL ...` straight to
`cli_enum.main(argv)` unchanged. The orchestrator path also invokes them
— this is what keeps the existing 57 tests valid through phase 1.

## 6. Module taxonomy

| Stage    | Module           | Default | Requires           | Notes                                                                         |
| -------- | ---------------- | ------- | ------------------ | ----------------------------------------------------------------------------- |
| sweep    | sweep            | on      | `nmap`             | existing                                                                      |
| enum     | masscan          | on      | `masscan`          | core of enum; not separately toggled below this                               |
| enum     | nmap-sv          | on      | `nmap`             | core of enum                                                                  |
| enum     | probe-ftp        | on      | —                  | existing                                                                      |
| enum     | probe-ssh        | on      | —                  | existing banner                                                               |
| enum     | probe-web-basic  | on      | —                  | existing `<title>`                                                            |
| enum     | probe-web-deep   | on      | —                  | **new** — server / X-Powered-By headers, robots.txt, redirect chain, favicon hash |
| enum     | probe-tls-cert   | on      | —                  | **new** — subject / SAN / issuer / expiry; feeds the feedback pass            |
| enum     | probe-smb        | on      | `nxc` (soft)       | existing null/guest                                                           |
| enum     | probe-db         | on      | —                  | **new** — 3306 / 5432 / 1433 / 27017 / 6379 banner + version                  |
| enum     | probe-mail       | on      | —                  | **new** — 25 / 465 / 587 / 110 / 143 / 993 / 995 banner + STARTTLS            |
| enum     | probe-ldap       | on      | —                  | **new** — 389 / 636 / 3268 anon bind, RootDSE                                 |
| enum     | probe-snmp       | on      | —                  | **new** — UDP/161 `public` / `private` (timeout-capped)                       |
| enum     | probe-rdp        | on      | —                  | **new** — 3389 TLS cert; SAN feeds the feedback pass                          |
| enum     | probe-nfs        | on      | `showmount` (soft) | **new** — 2049 `showmount -e`                                                 |
| enum     | probe-ptr        | **off** | —                  | **new** — reverse-DNS lookup per live host; opt-in to avoid surprise resolver traffic |
| feedback | vhost-pass       | on      | —                  | **new** — single extra pass: new hostnames as targets + vhost `Host:` headers |
| nuclei   | nuclei           | on      | bootstrapped       | existing                                                                      |
| nessus   | nessus           | on      | config.ini         | auto-skip if config missing                                                   |
| smb      | smb-mass         | on      | `nxc`              | existing `pt-smb`                                                             |
| report   | report-xlsx      | on      | —                  | **new** — `report.xlsx` with summary / hosts / services / nuclei / smb / nessus-link sheets |

The `masscan` and `nmap-sv` modules don't get individual `--no-` flags —
disabling them in isolation makes no sense; operators skip the whole
`enum` stage with `--no-enum`. They are listed so the registry has a
single source of truth for prereqs (used by `--dry-run` and the run
manifest).

## 7. CLI UX

```
# default — runs everything that can run
pt-recon -n acme -r 10.0.0.0/24

# disable at the stage tier
pt-recon -n acme -r 10.0.0.0/24 --no-nuclei --no-report

# disable individual probes
pt-recon -n acme -r 10.0.0.0/24 --no-probe-snmp --no-probe-nfs

# ad-hoc single stage via subcommand
pt-recon enum -iL hosts.txt -o enum.xlsx
pt-recon sweep -r 10.0.0.0/24

# inspection
pt-recon -n acme -r ... --dry-run     # print planned stages + module set + skip reasons; exit 0
pt-recon --list-modules               # print the registry as a table; exit 0
```

Conventions:

- `--no-<name>` disables any default-on module; `--<name>` enables a
  default-off module.
- Module flag names are the registry name verbatim (kebab-case).
- Stage flag off implies all its modules off.
- Subcommands are exactly today's per-tool binaries minus the `pt-`
  prefix; their flags and exit codes are unchanged from the documented
  contracts in `cli_*.py`.

## 8. Orchestrator data flow

```
sweep ──► enum ──► feedback ──► nuclei ──► nessus ──► smb ──► report
 │         │         │            │          │         │        │
 live-     enum.     enum.xlsx    nuclei.    Nessus    smb.    report.
 hosts.txt xlsx      (pass=2      jsonl      scan id   xlsx    xlsx
           (pass=1   rows         + targets  + UI URL          + run.json
            rows)    appended)    .txt
```

### 8.1 Feedback pass (single extra pass)

Between enum and nuclei the orchestrator runs one extra pass:

1. Collect candidate hostnames from pass-1 enum results: `probe-tls-cert`
   SANs, `probe-rdp` cert SANs, `probe-smb` host field. PTR lookup is
   considered but kept opt-in via a separate `--probe-ptr` (default off)
   to avoid surprising operators with reverse-DNS traffic.
2. Resolve each hostname. Keep it only if its IP is already in the
   engagement's target set — the feedback pass never expands scope.
3. Re-run only the web-touching modules (`probe-web-basic`,
   `probe-web-deep`, `probe-tls-cert`) against the open web ports of
   those IPs, with `Host: <hostname>` on every request.
4. Append rows to `enum.xlsx` with `pass=2` and `vhost=<hostname>` set.
5. No further iteration — discoveries in pass 2 are recorded, not chased.

Downstream stages (`nuclei`, `nessus`, `smb`, `report`) see the merged
pass-1 + pass-2 enum output and therefore implicitly cover the new
vhosts.

## 9. Error handling, prereqs, exit codes

### 9.1 Uniform auto-skip rule

Before invoking a module's `run`, the orchestrator checks every entry in
`module.requires`:

- For `Tool("foo")`: `shutil.which("foo")` must return a path.
- For `ConfigKey(section, key)`: the loaded INI must contain the key
  with a non-empty value.
- For `Soft(...)`: the requirement is informational; the module runs and
  reports the missing prerequisite per host or in its own log line, but
  is not skipped.

If a non-soft requirement fails, the orchestrator logs exactly one
`WARN` line:

```
[WARN] <module> skipped: <reason>
```

records `status=skipped` (with `reason`) in the run manifest, does not
run the module, and does not fail the enclosing stage.

### 9.2 Exit codes (orchestrator)

| Code | Meaning                                                       |
| ---- | ------------------------------------------------------------- |
| 0    | every attempted stage succeeded (skipped modules don't count) |
| 1    | one or more stages exited non-zero                            |
| 2    | argument / target / config error before any stage ran         |
| 130  | interrupted (Ctrl-C)                                          |

### 9.3 Exit codes (subcommands)

Inherited unchanged from the contracts documented in each `cli_*.py`
module docstring and `--help` epilog. Subcommand runs never invoke the
registry's auto-skip path — if a required tool is missing, the
subcommand fails with code 3 the way it does today.

## 10. Output layout & report schema

### 10.1 Engagement directory

`~/tools/recon/output/<name>/`:

```
live-hosts.txt          sweep output
enum.xlsx               enum + feedback rows (pass column distinguishes)
nuclei.jsonl            nuclei findings
nuclei.jsonl.targets.txt nuclei input
smb.xlsx                smb stage output
report.xlsx             NEW master workbook
run.json                NEW manifest
run.log                 NEW orchestrator log (tee of INFO output)
```

### 10.2 `run.json` manifest

A small JSON document written at the end of the orchestrator run (and
incrementally as each stage finishes, so a Ctrl-C still leaves a usable
partial manifest):

```json
{
  "engagement": "acme",
  "started_at": "2026-06-22T14:00:00Z",
  "finished_at": "2026-06-22T14:42:11Z",
  "targets": {"count": 254, "source": "-r 10.0.0.0/24"},
  "stages": [
    {"name": "sweep", "status": "ok", "elapsed_s": 12.4, "modules_run": ["sweep"], "modules_skipped": []},
    {"name": "enum",  "status": "ok", "elapsed_s": 312.8, "modules_run": ["masscan", "nmap-sv", "probe-ftp", ...], "modules_skipped": [{"name": "probe-nfs", "reason": "showmount not on PATH"}]},
    ...
  ],
  "exit_code": 0
}
```

The `report` stage consumes `run.json` to populate the `summary` sheet.

### 10.3 `report.xlsx` sheets

| Sheet         | Rows                          | Columns                                                                       |
| ------------- | ----------------------------- | ----------------------------------------------------------------------------- |
| `summary`     | one per stage                 | stage, status, modules-run, modules-skipped (+reason), elapsed                |
| `hosts`       | one per IP                    | ip, hostnames (cert SAN ∪ PTR ∪ SMB), open-port count, OS hint                |
| `services`    | flattened enum (pass 1 + 2)   | ip, port, state, http-title, service, finding, vhost, pass, tech-header       |
| `nuclei`      | flattened nuclei.jsonl        | host, port, template-id, severity, matched-at, info; red-fill on high/critical |
| `smb`         | flattened smb.xlsx            | ip, host, os, signing, smbv1, finding                                         |
| `nessus-link` | one row                       | scan name, scan id, UI URL, status (if `--wait` was used)                     |

Conditional formatting reuses `common._RED_FILL` and matches the existing
anon/null/guest highlighting convention on the `services` sheet, plus
high/critical highlighting on the `nuclei` sheet.

## 11. Testing strategy

- All 57 existing tests stay green: `cli_*.main(argv)` signatures don't
  change.
- New test surfaces:
  - `tests/test_modules.py` — registry: registration, lookup, generated
    `--no-<name>` flags, prereq-skip semantics (mock `shutil.which` and
    INI loader).
  - `tests/test_probes_<name>.py` — one per new probe (`db`, `mail`,
    `ldap`, `snmp`, `rdp`, `nfs`, `web-deep`, `tls-cert`); mock `socket`
    / `requests` / `subprocess` in the same style as
    `tests/test_probes.py`.
  - `tests/test_cli_recon.py` additions — stage skipping, module
    skipping, `--dry-run` output, `--list-modules` output, exit codes
    for the new auto-skip path, feedback-pass plumbing (mock pass-1
    enum to return a cert SAN → assert pass-2 web call with `Host:`
    header).
  - `tests/test_report.py` — synthesize stage artifacts in a tmpdir →
    call report builder → assert sheet / row / column shape and red-fill
    on high-severity rows.
- No live network in tests; everything mocked.

## 12. Phased delivery

Each phase is its own spec + plan + branch; tests run green between
phases. The order is strict — phase 1 is load-bearing, phase 4 depends
on phase 3's cert SAN data, phase 5 is most valuable last.

### Phase 1 — Umbrella architecture (this spec is its parent)

- Add `recon/modules.py` with `@module` decorator, `Module` dataclass,
  and `Requirement` types.
- Convert existing functionality (sweep, masscan, nmap-sv,
  probe-ftp/ssh/web-basic/smb, nuclei, nessus, smb-stage) into registered
  modules.
- Rewire `cli_recon.py` to generate flags from the registry and iterate
  modules; add `--dry-run` and `--list-modules`.
- Add subparser routing in `pt-recon` to `cli_*.main` for ad-hoc
  per-stage invocation.
- Flip `nessus` and `smb` default-on; auto-skip honors §9.1.
- Emit `run.json` and `run.log` per engagement.
- **Delete `bin/pt-sweep`, `bin/pt-enum`, `bin/pt-nuclei`,
  `bin/pt-nessus`, `bin/pt-smb`** — single-binary commitment.
- Tests: registry, dispatch, generated flags, auto-skip, exit codes.
- **No new probes in this phase.**

### Phase 2 — Service-coverage probes (gap B)

- `probe-db` — 3306 (MySQL handshake), 5432 (Postgres SSLRequest /
  startup), 1433 (MSSQL TDS prelogin), 27017 (Mongo `isMaster`), 6379
  (Redis `PING`/`INFO` if unauthenticated).
- `probe-mail` — 25 / 465 / 587 / 110 / 143 / 993 / 995: banner + STARTTLS
  capability where applicable.
- `probe-ldap` — 389 / 636 / 3268: anonymous bind, RootDSE attribute
  read.
- `probe-snmp` — UDP/161: `public` and `private` community against
  `sysDescr.0`, short timeout.
- `probe-rdp` — 3389: TLS handshake, certificate subject + SAN (SAN is
  surfaced to the feedback pass in phase 4).
- `probe-nfs` — 2049: `showmount -e <ip>` if the binary is available
  (soft requirement).
- One test file per probe.

### Phase 3 — Web depth + TLS cert SAN (gap A)

- `probe-web-deep` — server header, X-Powered-By, common tech markers in
  HTML, robots.txt fetch (record paths discovered), redirect chain
  capture, favicon-hash (mmh3 if installed; sha256 fallback).
- `probe-tls-cert` — pure-Python `ssl.SSLContext` connect; capture
  subject CN, SAN, issuer, NotBefore/NotAfter. SAN entries are exported
  for the feedback pass.

### Phase 4 — Feedback loop (gap C)

- Add `feedback` stage between enum and nuclei.
- `vhost-pass` module reads pass-1 enum, computes the hostname→IP
  candidates, and invokes the registered web-touching modules a second
  time with `Host:` header set.
- `enum.xlsx` gains `pass` (int, 1 or 2) and `vhost` (str) columns; the
  workbook writer in `common.py` is extended accordingly.

### Phase 5 — Consolidated report (gap D)

- `report-xlsx` module assembles `report.xlsx` from `enum.xlsx`,
  `nuclei.jsonl`, `smb.xlsx`, and `run.json`.
- Six sheets per §10.3; reuses `common._RED_FILL`.
- Summary is the first sheet (default tab on open).

## 13. Open questions

None at draft time. To be filled in during user review.
