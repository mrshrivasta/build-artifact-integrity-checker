# Build Artifact Integrity Checker

**A real, no-mock-data SHA-256 build-output integrity scanner — CLI + Web App.**
Computes real `hashlib.sha256` hashes of every real file in a real build-output directory (e.g. `dist/`, `build/`, `target/`) and diffs that snapshot against the baseline recorded on the previous scan of the SAME path, to detect real unauthorized modifications, deletions, additions, and suspicious timestamp rollbacks between builds.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ DISCLAIMER (READ BEFORE USE)

This software is provided **strictly for educational, defensive-security, and release-engineering purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Local baseline only — no external "known good" source.** This tool establishes its baseline **entirely from your own first scan** of a given target path (stored locally in SQLite for the web app, or in a local `.bai_baseline.json` cache file for the CLI). It does **not** fetch, verify against, or trust any external "known good" hash registry, package repository, transparency log, or vendor-published checksum. A finding of "no change" only means the artifact matches your own previously recorded snapshot — it does **not** mean the original baseline itself was trustworthy.
- **Authorized use only.** Run this tool **only** against directories, build pipelines, and files that you own or for which you have explicit, documented authorization to inspect.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including data loss, broken builds, missed tampering, or false alarms — arising from the use, misuse, or inability to use this software.
- **Not a certified audit.** This tool is **not a substitute** for a professional security review, a signed/attested supply-chain verification system (e.g. Sigstore, in-toto, SLSA provenance), or a review by a qualified security professional. Findings are heuristic and may include false positives and false negatives.
- **No guaranteed detection.** Absence of findings does **not** mean a build artifact is safe. This tool checks a specific, limited set of hash/size/mtime-based signals only, and only between scans it has itself performed.
- **Read-only by design.** The Security Engine only reads file bytes to compute hashes (`open(..., "rb")`, `hashlib.sha256`) and reads filesystem metadata (`os.path.getsize`/`getmtime`) — it never writes to, deletes, or modifies scanned files. Verify this yourself by reading `app/security_engine/__init__.py` before running it on anything important.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to scan a given build output, **do not run this tool against it.**

---

## Who should use this project

- Release engineers and build/CI pipeline owners who want a real, scriptable way to detect unexpected changes to build artifacts between pipeline runs.
- DevSecOps teams investigating supply-chain integrity of `dist/`, `build/`, `target/`, or container-layer output directories.
- Security students and self-learners studying build-artifact tampering, checksum diffing, and supply-chain integrity concepts.
- CI/CD pipelines that want an artifact-integrity gate (the CLI exits non-zero when a real, actionable change is detected since the last cached baseline).

## Why use this project

- **Real data only** — every result comes from a live `hashlib.sha256` read of real file bytes on the current machine, diffed against a real snapshot from a real prior scan. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py` operating on plain context dicts. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/CI, with its own local baseline cache file) and the web app (for dashboards/teams, backed by SQLite) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a scanner** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external network calls at scan time.

---

## Architecture

```
build-artifact-integrity-checker/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action (looks up prior DB snapshot, wires it into ScanEngine)
│   ├── security_engine/      # Core real sha256-hashing + snapshot-diffing engine
│   ├── detection_rules/      # 6 documented detection rules (BAI-001..006)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite) — ScanResult.metadata_snapshot stores the real baseline JSON
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules — own local .bai_baseline.json cache
├── tests/                     # pytest suite — real temp-filesystem hashing/diffing + real Flask app
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, depth, exclusions, alert threshold)

---

## How the diffing works

1. Given a real local directory path (a "build output" directory), the engine walks it (bounded depth) and, for every real file it can read, computes a real `hashlib.sha256` digest of its actual bytes plus its real size and mtime.
2. It builds a structured snapshot: `{relative_path: {"sha256": ..., "size": ..., "mtime": ...}}`.
3. It looks up the **most recent prior scan of the same target_path** (same user, in the database for the web app; the `.bai_baseline.json` cache entry for the CLI) and diffs the two real snapshots path-by-path.
4. Every difference is run through the six pure detection rules below and turned into a Finding.
5. The new snapshot is then persisted as the baseline for the **next** scan of that same path.

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| BAI-001 | Hash Changed, Size Unchanged (Disguised Modification) | Critical | Real SHA-256 hash changed between scans while size stayed identical — a size-preserving tamper pattern |
| BAI-002 | Hash Changed, Size Changed | High | Real SHA-256 hash changed between scans and size also changed — a normal-looking but still unexpected content modification |
| BAI-003 | Build Artifact Removed | Medium | A file present in the prior scan's snapshot is missing entirely from the current scan |
| BAI-004 | New Build Artifact Added | Medium | A new file appeared in the current scan that was not present in the prior baseline |
| BAI-005 | Baseline Established | Low / informational | This is the first scan ever recorded for this target path — no prior baseline exists, so this run establishes it |
| BAI-006 | Suspicious Mtime Rollback | Low | A file's hash is unchanged but its real mtime moved backward compared to the previous scan — sometimes used to mask tampering |

---

## Setup & Run

### Requirements
- Python 3.9+
- Linux, macOS, or any POSIX-like OS

### Install

```bash
git clone <this-repository-url>
cd build-artifact-integrity-checker
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
BAI_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1              # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data (including each scan's real hash-snapshot baseline) live in a local SQLite file at `instance/bai.db`. To get a real diff finding, run a scan against a directory, then run a scan of the **same path** again after changing a file in it.

### Run the CLI

The CLI has no web session or database, so it keeps its own real local baseline cache file (`.bai_baseline.json` by default, written in the current directory) keyed by the absolute target path. The first scan of a path records a baseline (BAI-005); every later scan of the same path diffs against that cached baseline and then overwrites it with the new snapshot.

```bash
python3 cli/main.py scan ./dist                       # first run: establishes the baseline
python3 cli/main.py scan ./dist                       # second run: real diff against the cached baseline
python3 cli/main.py scan ./dist --json
python3 cli/main.py scan ./dist --csv findings.csv
python3 cli/main.py scan ./dist --baseline-file /tmp/ci-baseline.json   # custom cache location, e.g. per CI job
python3 cli/main.py rules
python3 cli/main.py scan --help                        # full flag documentation, including --baseline-file
```

The CLI exits with status code `1` if any actionable finding (anything other than the informational BAI-005 baseline) is detected since the last cached scan — useful as a CI gate — and `0` otherwise.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

All 23 tests use real temporary files/directories with real content changes, real `hashlib.sha256` hashing, and a real two-scan diff cycle (plus a real Flask app/DB for the web-route tests) — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Build Artifact Integrity Checker check?**
It computes a real SHA-256 hash, size, and mtime for every file in a real build-output directory, and compares that snapshot against the previous scan of the same path to flag hash changes (with or without a size change), unexpected deletions, unexpected additions, and suspicious timestamp rollbacks.

**Does it fetch a "known good" hash from anywhere external?**
No. The baseline is established entirely from your own first scan of that path and stored locally (SQLite for the web app, a JSON cache file for the CLI). It never contacts an external checksum registry, package index, or transparency log.

**Who should use it?**
Release engineers, DevSecOps teams, and CI/CD pipeline owners who want to detect unauthorized changes to build artifacts they own or are authorized to assess.

**Is it a replacement for a professional security audit?**
No. It is an educational and productivity aid only — see the Disclaimer section above.

**Does it modify my files?**
No. It only reads file bytes to hash them and reads filesystem metadata. It never writes to, deletes, or changes the scanned artifacts themselves.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
