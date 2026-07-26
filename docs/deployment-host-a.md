# Host `a` deployment record and runbook

This document records the deployment discovered and updated on 2026-07-26. It
contains no RPC credentials or environment-variable values. The SSH alias
`a` is assumed to be configured in the operator's local SSH configuration.

## Current deployment

| Item | Value |
| --- | --- |
| SSH alias | `a` |
| Remote hostname | `vultr` |
| systemd unit | `tapscript-weak-finder.service` |
| Deployed revision | `9b68d408054c0fb9cdd123a991262534e49708d0` (`9b68d40`, `Expand bounded TapScript witness search`) |
| Deployment time | `2026-07-26T13:35:13Z` (`2026-07-26 21:35:13` Asia/Shanghai) |
| Release source | `/opt/tapscript-weak-finder/releases/9b68d40` |
| Active source link | `/opt/tapscript-weak-finder/source` |
| Installed binary | `/opt/tapscript-weak-finder/bin/tapscript-weak-finder` |
| Binary SHA-256 | `fa1a55d9ec7afba46538c2a82cbbf52c94c05bda789df74f712c78387939d3cb` |
| Deployment metadata | `/opt/tapscript-weak-finder/DEPLOYMENT` |
| Previous source snapshot | `/opt/tapscript-weak-finder/releases/03f9872` (revision `03f98728c15ffba5e2b1e4060eba21334a442f16`) |

The release was created from `git archive 9b68d40`, not from a mutable local
worktree. The uploaded archive SHA-256 was
`f29ad507ddf9e7507220bdcf1db8715c18fd82f51030f531b42f011fdad85ca7`.
The source hashes checked after extraction were:

| File | SHA-256 |
| --- | --- |
| `src/analyzer.rs` | `cade0f8c6a53812ba035b65d7d6bcc5bd6ff4010a7440c352717e4234ae94078` |
| `src/db.rs` | `805606d7aae6cef759c69cae3e51b51597a7f123ebda7663503f5b75763e4dd5` |
| `src/taproot.rs` | `aeb935a825317e3a2c5fe96423a5ae839496147f55c0fd514649bf8463a971af` |

The previous installed binary was from source revision `03f9872`; its SHA-256
was `0c017f93f746aff32a76570256d2ada5f2f3174fe7c9a141eb213dcdcc20a6de`.
Both revisions identify themselves as crate version `0.1.0`, so the Git
revision and binary hash—not `--version` alone—must be used to identify the
deployed code.

## Service configuration

The effective service configuration discovered on 2026-07-26 is:

```text
User=tapscript-scan
Group=tapscript-scan
WorkingDirectory=/var/lib/tapscript-weak-finder
EnvironmentFile=/etc/tapscript-weak-finder/env
ExecStart=/opt/tapscript-weak-finder/bin/tapscript-weak-finder \
  --db /var/lib/tapscript-weak-finder/audit.sqlite \
  scan \
  --start-height 709632 \
  --output json \
  --reorg-retention-blocks 144 \
  --rpc-max-response-mib 64 \
  --min-free-disk-mib 4096 \
  --max-in-memory-p2tr-utxos 1000000
Restart=on-failure
RestartSec=300
TimeoutStopSec=300
KillSignal=15
StandardOutput=append:/var/log/tapscript-weak-finder/blocks.ndjson
StandardError=append:/var/log/tapscript-weak-finder/scanner.log
```

The environment file was `root:root` mode `0600` at inspection time. Do not
copy its contents into this repository or diagnostic output.

Useful paths and ownership:

| Purpose | Path | Observed ownership/mode |
| --- | --- | --- |
| SQLite database | `/var/lib/tapscript-weak-finder/audit.sqlite` | `tapscript-scan:tapscript-scan`, `0644` |
| Runtime directory | `/var/lib/tapscript-weak-finder` | mode `0750` |
| Structured scan log | `/var/log/tapscript-weak-finder/blocks.ndjson` | managed by the service |
| Error log | `/var/log/tapscript-weak-finder/scanner.log` | managed by the service |
| Secret configuration | `/etc/tapscript-weak-finder/env` | `root:root`, `0600` |

The database uses WAL mode, so `audit.sqlite-wal` and `audit.sqlite-shm` may
exist while the service is running. Do not copy only the main database file
and assume it is a consistent snapshot.

## State at the 2026-07-26 upgrade

The last explicit metadata sample before stopping the old process was:

```text
start_height=709632
next_height=720754
max_scanned_height=720753
target_height=959678
oldest_reorg_safe_height=720610
reorg_retention_blocks=144
```

The old process continued scanning between that sample and the actual stop.
The new process's startup event recorded `start_height=720769` and
`resumed=true`, establishing that the effective handoff was after height
720768.

The old database contained 10,481 scanned blocks at the initial audit, 14
analysis runs, zero weakness rows, and 14 compacted TapScript leaves. All 14
analysis runs were `no_proof_found` under this old search configuration:

```json
{"effective_max_witness_items":4,"requested_max_witness_items":4,"witness_atoms":["empty","01"]}
```

Continuing the scan does not re-analyze those 14 historical, compacted leaves
with the expanded analyzer. A deliberate rescan is required if that historical
coverage matters. `no_proof_found` is not a safety proof.

After the upgrade:

```text
service_state=active/running
main_pid=56158
restart_count=0
start_height=709632
resume_event_start_height=720769
resume_event_resumed=true
next_height=720884
max_scanned_height=720883
target_height=959701
weakness_count=0
scanner_log_size=0
```

The new process resumed after height 720768 rather than starting at genesis or
at 709632. The `--start-height` argument identifies the existing scan; the
persisted `next_height` is the resume cursor. The values above are from the
final review sample, about 162 seconds after restart. Startup also migrated the
`weaknesses` table by adding `proof_strategy`. The migration was low risk in
this deployment because the table contained no rows.

The target height is refreshed from Bitcoin Core on startup. It therefore
changed from 959678 to 959701 during this deployment.

## Deployment verification performed

The old service remained running while the new release was built. On the
remote host:

- `cargo test --all-targets --locked --offline` passed: 41 passed, 2 ignored;
- `cargo build --release --locked --offline` succeeded;
- the built and installed binary hashes matched;
- the service started once with no restart loop;
- the database migration was observed through read-only SQLite inspection;
- the startup event explicitly reported `start_height=720769` and
  `resumed=true`;
- new-process block results advanced from 720769 to at least 720883;
- the process arguments continued to match the systemd unit.

`cargo fmt --all -- --check` and strict Clippy were also attempted with the
host's Rust 1.97.1 toolchain. The committed source had already passed these
checks locally, but remote Rust 1.97.1 reported:

- rustfmt-only layout differences;
- two new `collapsible_if` warnings;
- one new `manual_is_multiple_of` warning.

The deployed source was intentionally not reformatted or edited on the server,
so it remains byte-identical to revision `9b68d40`. These are toolchain-version
style differences, not build or test failures. The remote toolchain observed
at deployment was Cargo 1.97.1, rustc 1.97.1, Git 2.47.3, and Python 3.13.5.
The host did not have the `sqlite3` CLI; read-only checks used Python's standard
`sqlite3` module with `mode=ro`.

At inspection time the host had about 75 GiB total disk with 57 GiB free,
3.8 GiB RAM with about 3.2 GiB available, and 2.3 GiB swap.

## Routine checks

Service identity and restart status:

```bash
ssh a 'systemctl show tapscript-weak-finder.service \
  -p ActiveState -p SubState -p MainPID -p NRestarts \
  -p ExecMainStatus -p ActiveEnterTimestamp --no-pager'
```

Exact deployed revision and binary:

```bash
ssh a 'cat /opt/tapscript-weak-finder/DEPLOYMENT &&
  readlink -f /opt/tapscript-weak-finder/source &&
  sha256sum /opt/tapscript-weak-finder/bin/tapscript-weak-finder'
```

Recent progress and errors:

```bash
ssh a 'tail -n 20 /var/log/tapscript-weak-finder/blocks.ndjson'
ssh a 'tail -n 50 /var/log/tapscript-weak-finder/scanner.log'
```

Read the persisted cursor without opening the database for writes:

```bash
ssh a 'python3 - <<'"'"'PY'"'"'
import sqlite3

uri = "file:/var/lib/tapscript-weak-finder/audit.sqlite?mode=ro"
connection = sqlite3.connect(uri, uri=True)
metadata = dict(connection.execute("SELECT key, value FROM metadata"))
for key in (
    "chain",
    "start_height",
    "next_height",
    "target_height",
    "oldest_reorg_safe_height",
    "reorg_retention_blocks",
):
    print(f"{key}={metadata.get(key)}")
print(
    "max_scanned_height="
    + str(connection.execute("SELECT MAX(height) FROM scanned_blocks").fetchone()[0])
)
PY'
```

An active systemd state alone is not enough to establish scanner health.
Confirm that block heights advance, `NRestarts` stays stable, and the error log
does not show repeated failures.

## Future upgrade procedure

Use an immutable release directory named after the Git revision:

1. Create an archive from a committed revision with `git archive`.
2. Upload and extract it under
   `/opt/tapscript-weak-finder/releases/<revision>`.
3. Verify source hashes and run tests/builds before stopping the old service.
4. Record the database's `next_height` and `max_scanned_height` read-only.
5. Stop `tapscript-weak-finder.service`.
6. Point `/opt/tapscript-weak-finder/source` to the new release.
7. Install the new binary through a temporary filename and atomically rename
   it over the active binary.
8. Update `/opt/tapscript-weak-finder/DEPLOYMENT`.
9. Start the service and verify schema migrations, the resume cursor, advancing
   block logs, and restart count.

Do not read or print `/etc/tapscript-weak-finder/env` during a routine upgrade.
Do not run Cargo directly inside the active source link after deployment.

## Explicit reset procedure

The 2026-07-26 operator authorization allowed discarding the online database
and scan progress if recovery required a clean deployment. This authorization
should not be assumed for unrelated future incidents; confirm the intended
scope again before deleting state.

When a reset is explicitly authorized:

1. Stop the service and verify it is inactive.
2. Remove only these exact scanner-owned state files:
   `/var/lib/tapscript-weak-finder/audit.sqlite`,
   `/var/lib/tapscript-weak-finder/audit.sqlite-wal`, and
   `/var/lib/tapscript-weak-finder/audit.sqlite-shm`.
3. If logs must also be reset, truncate only
   `/var/log/tapscript-weak-finder/blocks.ndjson` and
   `/var/log/tapscript-weak-finder/scanner.log`.
4. Start the service and verify a newly initialized database, the configured
   start height, advancing block results, and no restart loop.

The production scanner must remain read-only with respect to Bitcoin Core.
Never add wallet, signing, transaction-submission, block-submission, or mining
RPCs to this deployment.
