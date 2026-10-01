# EC2 Monitor Bot

The bot collects host-level CPU, memory, network, uptime, process, and disk
metrics for local or SSH-managed instances and sends reports to the configured
Telegram chat. Copy `.env.example` to `.env` and replace every placeholder with
the values for your deployment. Keep `.env`, SSH keys, and bot credentials
private; do not commit them.

## Host and disk configuration

Each host uses the existing indexed settings `INSTANCE_<N>_NAME`,
`INSTANCE_<N>_IP`, `INSTANCE_<N>_CHAT_ID`, and (for remote hosts)
`INSTANCE_<N>_KEY` plus `INSTANCE_<N>_SSH_USER`. The bot keeps the existing
sequential instance order and stops when a required name, IP, or chat ID is
absent.

Optional host settings:

- `INSTANCE_<N>_OS=linux` or `INSTANCE_<N>_OS=windows` explicitly selects the
  remote host type. If omitted, the existing `administrator`/`admin` SSH-user
  inference remains the fallback (Windows); other SSH usernames default to
  Linux. An explicit value must be `linux` or `windows`.
- `INSTANCE_<N>_DISK_PATHS` is a semicolon-separated list of additional
  psutil-readable disk paths. The primary path is always included and is
  deduplicated against the additional entries: `/` for Linux and local Linux,
  or `C:\` for Windows. Do not leave an empty entry between semicolons.

Example Windows database host configuration (use the actual mount points for
the database host's SQL data and log volumes):

```dotenv
INSTANCE_3_NAME=Windows database host
INSTANCE_3_IP=replace_with_windows_ec2_address
INSTANCE_3_CHAT_ID=replace_with_distinct_windows_host_chat_id
INSTANCE_3_KEY=/path/to/windows-monitor-key.pem
INSTANCE_3_SSH_USER=replace_with_windows_ssh_user
INSTANCE_3_OS=windows
INSTANCE_3_DISK_PATHS=D:\SQLData;E:\SQLLogs
```

The Windows host must accept the configured SSH key and have an SSH server,
Python available as `python`, and `psutil` installed for that Python. Its SSH
command shell must allow the bot's standard `python -c` invocation. The bot
collects host filesystem capacity only; disk volume readings are **not** SQL
engine health checks, database connectivity checks, or SQL query monitoring,
and no SQL username or password is required.

Assign the Windows host a distinct Telegram chat ID so commands in that chat
select the database host without ambiguity. After deployment, send `/disk` in
that chat and verify that the primary `C:\` path and each configured data/log
path show used percentage, free GB, and total GB. An unreadable or nonexistent
path is shown as unavailable and does not erase other host metrics. Live
verification requires access to the operator's actual host, SSH account, and
volume paths.

The CSV history remains primary-disk-only and retains its existing fields.

## Security scanning and network evidence

`/security` and the nightly job collect the same structured evidence from local
and SSH-remote hosts, on Linux and on Windows. Each socket becomes a
`network.observations` entry
with the protocol, local/remote address and port, connection state, the owning
process (PID, name, executable, command line, user) and the Docker container
publication when one can be proven, plus a `bind_scope`
(`loopback-only`, `private-interface`, `all-interfaces`, `public-interface` or
`unknown`), a `direction` (`inbound`, `outbound` or `uncertain`), a
`classification` (`benign`, `expected`, `informational`, `needs_review`,
`suspicious`, `high_risk` or `unknown`), a `confidence` value, and a `reason`
with supporting `evidence`. Missing data is reported as `unknown` instead of
being treated as safe.

The old `network.unexpected_listening` and `network.external_connections` keys
are still produced as compatible projections of the same evidence. They carry
no owner field, they never report an inbound server-side connection as an
external outbound connection, and they are no longer truncated. Nothing is
dropped because of a port number, an address, or an ephemeral port: a
classification only becomes `expected` when a configured identity matches the
collected evidence.

`network.risk` is derived deterministically from the observations: verified
expected traffic is negligible, an unresolved externally exposed listener or an
outbound connection that matches no configured service is at least medium, a
concrete deviation is suspicious, `high` requires corroboration from another
signal (suspicious process, temporary-directory binary, failed service, or auth
log entries), and an incomplete or failed scan yields an unknown posture that is
never presented as clean.

### Windows hosts

Set `INSTANCE_<N>_OS=windows` to select the Windows remote collector for that
instance. That sends a Windows-native program (`powershell -NoProfile` queries and
`psutil` only) and never the Linux program, which has no `systemctl`, cron spool,
Linux auth log or Linux container CLI. Windows is a new collector, never a new
policy: the same classification, direction, bind-scope, confidence and risk code
runs on its output.

A Windows host produces a **partial scan by design**. Concepts that have no
Windows equivalent here — the Linux cron spool, the Linux sensitive-directory
scan, systemd units, and an unelevated read of the Security event log — are
reported in `findings["unavailable"]` by name rather than returned as an empty
success, which forces `scan_status: "partial"` and an `incomplete` posture. The
report always states which categories are unavailable, and a repeated per-item gap
is collapsed into one counted line so a long list of identical denials cannot push
that statement out of view.

### What one Telegram message can carry

There is exactly **one canonical evidence block**. The aggregate `Network summary`
precedes it and reports totals for all observations; the detail block then renders
each retained observation once, in adverse-first order. Per-classification display
caps (`NEEDS_REVIEW_SHOWN`, `UNKNOWN_SHOWN`, and one pool shared by the verified
classifications) bound what a message carries — they are **separate from evidence
retention**. `findings["network"]["observations"]` keeps every observation, and the
prompt, the authoritative assessment and the risk computation always use the full
list whatever the display caps say. Every classification is always reported, with
an explicit omitted count including `0 omitted`.

The AI commentary is advisory only and is delivered after the assessment in
separate chunks. Chunk 1 carries the timestamp and the rule; every continuation
chunk repeats the instance, marks itself `2/N`, and repeats that advisory text
cannot change the authoritative risk. No chunk can be read on its own as
authoritative.

### Durable update offset

The Telegram `getUpdates` offset is persisted before a command's handler runs, so a
crash mid-command can only skip a command, never run one twice. It is written
atomically as `telegram_offset.json` in the state directory — mode `0600` inside a
`0700` directory that is never inside the repository. Set `MONITOR_BOT_STATE_DIR`
to choose it, otherwise `XDG_STATE_HOME/monitor_bot` is used, then
`~/.local/state/monitor_bot`. A missing, empty, corrupt or non-positive stored
offset is treated as absent rather than blocking the poll loop.

### Optional per-instance security identities

These settings are opt-in per instance. With none of them set the scanner still
reports every observation; unresolved items are simply classified
`needs_review` rather than being marked expected.

| Setting | Purpose |
| --- | --- |
| `INSTANCE_<N>_SECURITY_BOT_EXE` | Exact executable of the monitor bot, for example the project virtualenv interpreter. |
| `INSTANCE_<N>_SECURITY_BOT_SCRIPT` | Exact script argument the bot must be running. |
| `INSTANCE_<N>_SECURITY_BOT_USER` | Expected owner user for the bot process. |
| `INSTANCE_<N>_SECURITY_BOT_HTTPS_DESTINATIONS` | Addresses or CIDRs (optionally `address:port`, separated by `;`) the bot may reach over HTTPS. |
| `INSTANCE_<N>_SECURITY_TAILSCALED_EXE` | Exact Tailscale client executable. |
| `INSTANCE_<N>_SECURITY_TAILSCALED_USER` | Expected owner user for the Tailscale client. |
| `INSTANCE_<N>_SECURITY_TAILSCALED_HTTPS_DESTINATIONS` | Addresses or CIDRs the Tailscale client may reach over HTTPS. |
| `INSTANCE_<N>_SECURITY_OTEL_CONTAINER_NAME` | Container name expected to publish the collector port. |
| `INSTANCE_<N>_SECURITY_OTEL_IMAGE_ID` | Optional image ID pin for that container. |

Notes on how they are used:

- The bot is only `expected` when the executable, the script argument, the owner
  user, a high local port, remote port 443 and a destination from this
  instance's list all match. A matching destination reached by a different
  process is still reported for review.
- The Tailscale client is only `expected` with a matching executable, user and
  configured destination. A process that merely carries a `tailscale` name is
  reported for review.
- A Docker-published collector port is only `expected` when the socket is
  actually held by the Docker userland proxy, exactly one running container
  publishes that host port to the expected container port over TCP, the
  container name matches, and the socket is bound to loopback only. A wildcard or
  non-loopback bind, an ambiguous publication, or a failed `docker` lookup is
  reported for review. Live verification of these settings requires access to the
  operator's own host, SSH account, and Docker socket permissions.
- Destination lists are validated when the configuration is loaded and are
  matched against each observed socket address, so a destination that changes
  simply stops matching and returns to review; no entry is treated as a general
  allowlist. Nothing in this configuration grants Docker socket permissions or
  changes SSH access.
- A failed SSH session, a missing remote `psutil`, a nonzero remote scanner exit
  status, or an unparsable response is reported as a failed scan with an unknown
  posture. It is never reported as clean.

### Unconfigured instances report `needs_review` with MEDIUM risk by design

With no `INSTANCE_<N>_SECURITY_*` values set, the scanner deliberately has no
identity to compare against. Every socket is therefore classified from the
evidence alone, an unresolved outbound connection or a network-reachable
unidentified listener is classified `needs_review`, and the authoritative risk
is at least `MEDIUM`. **This is the intended fail-safe, not a scanner fault:**
no default identity, no inferred trust, and no destination is ever guessed from
`sys.argv`, a process name, a port, or an address. A port number, an ephemeral
local port, or a container name on its own never makes an observation expected
or benign.

Which setting resolves which reported item, read on that host:

| Reported item | Setting that resolves it |
| --- | --- |
| An outbound HTTPS socket from the monitor bot reported as unmatched or not the configured bot | `INSTANCE_<N>_SECURITY_BOT_EXE`, `INSTANCE_<N>_SECURITY_BOT_SCRIPT`, `INSTANCE_<N>_SECURITY_BOT_USER` |
| A monitor-bot destination that stops matching after a change | `INSTANCE_<N>_SECURITY_BOT_HTTPS_DESTINATIONS` |
| An outbound HTTPS socket from the Tailscale client reported for review | `INSTANCE_<N>_SECURITY_TAILSCALED_EXE`, `INSTANCE_<N>_SECURITY_TAILSCALED_USER` |
| A Tailscale destination that stops matching after a change | `INSTANCE_<N>_SECURITY_TAILSCALED_HTTPS_DESTINATIONS` |
| A Docker-published collector listener reported for review because the workload cannot be confirmed | `INSTANCE_<N>_SECURITY_OTEL_CONTAINER_NAME` |
| A verified container whose image is not pinned | `INSTANCE_<N>_SECURITY_OTEL_IMAGE_ID` |

The scanner's own reason text names the same keys for the collector and the
Tailscale client, so the report points at the missing configuration.

Per-host verification steps, performed on the host itself (the bot never
verifies these for you):

1. Confirm the real executable, script argument, and owner user:
   `readlink -f /proc/<pid>/exe`, `tr '\0' ' ' < /proc/<pid>/cmdline`, and
   `ps -o user= -p <pid>`.
2. Confirm the real destination addresses actually used: `ss -tnp` (or
   `ss -unp`) alongside the collector's configured egress; use the observed
   remote address, not a hostname guess.
3. Confirm exactly one running container publication: `docker ps` and
   `docker inspect <container>` for the host port, container port, running
   state, name, and image ID.
4. Confirm the collector is bound to loopback only: `ss -ltnp` for the
   collector port. A `0.0.0.0` or host-IP bind is reported for review and is
   never suppressed.
5. Re-run `/security` and confirm the report still shows the item as
   `expected` with the configured destination entry, not merely as `needs_review`.

Setting these values requires the operator's own host, SSH account, and Docker
socket permissions; the bot only reads them from its environment.

