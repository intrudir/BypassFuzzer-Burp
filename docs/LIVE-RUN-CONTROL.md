# Pause, edit and resume

Every attack mode in Burp and the CLI can edit the remaining work in a run.
Completed exchanges remain evidence. Editing does not restart the scan from zero.

## Burp

Choose **Pause**, then **Edit run…**, or choose **Edit run…** directly to pause.
The dialog distinguishes **Pausing…** (admitted requests are finishing) from
**Paused**. **Apply & Resume** becomes available once the run is fully paused.
**Keep paused** closes the editor without applying changes.

The four sections are shared by Bypass, Sweep, IDOR and URL Validation:

- **Scope:** check exact hosts to exclude. Exclusions cover all ports for that
  socket hostname, including pending probes, controls, canaries and retries.
  These are run-local exclusions; Burp's project scope is unchanged. A mutated
  `Host` header does not change the socket host used by this check.
- **Throttle:** change total concurrency, per-host concurrency and the per-host
  requests/second cap. Adaptive backoff and Dashboard's extension-wide ceiling
  still apply; the cap is an upper bound, not a promised send rate.
- **Playbooks:** select the remaining catalog entries. Bypass and each Sweep
  inventory use shared catalog IDs. IDOR uses its existing IDOR playbook IDs;
  its dangerous-family confirmation still applies. URL Validation exposes
  `url.context.<ENUM>` and `url.attack.<ENUM>` selectors.
- **Headers:** replace the run's configured header list, remove named inherited
  headers, or change User-Agent variation. Use variation **DISABLED** for a
  fixed `User-Agent` header. Ordered duplicate configured headers remain supported.

An invalid edit leaves the run paused with its previous configuration. Successful
edits increment the configuration revision shown by **Edit run… (rN)**. Normal
setup controls describe the initial configuration; the run editor shows the
active configuration. Changes apply to this run rather than the next new scan.

Dashboard global pause is an independent overlay. A run can be paused and edited
while global pause remains active; **Apply & Resume** does not lift that overlay.
Conversely, **Resume All** does not lift a run's local pause.

Selecting a new playbook replans the original seeds and adds applicable unsent
work. Already attempted successful probes are not repeated. Disabled probes and
excluded targets do not send. If the only target is excluded, the run completes
with its retained results. Scope exclusions remain reversible while other work
keeps the run active. A completed run needs a new scan to add more work.

Header changes create a new comparison context: applicable Original, Authorized,
Target/anonymous and wildcard controls are refreshed before remaining mutations.
Authenticated Sweep still strips its selected authentication headers/cookies
from anonymous mutations and calibration. Header-only HTTP/0.9 limitations and
existing method/state-changing gates still apply. Completed rows retain their
original controls and configuration revision.

The shared manual retry queue follows the same scope, limits and header edits.
It refreshes matching controls and retains every control exchange. It replays
saved queued requests. Its selector lists saved probe groups, including legacy
groups without catalog IDs; it does not expose generation settings absent from
the saved metadata or add unsaved probes.

## CLI

All four modes accept `--control-file PATH`, also available as YAML
`execution.controlFile`. Existing plain `pause`, `resume` and `stop` commands
remain valid. Protect files containing header values with owner-only permissions.
Write commands atomically (write a sibling temporary file and rename it).

Read `PATH.status.json` to observe `pausing`, `paused`, `running` or `stopped`,
`inFlight`, `requestsSent`, `revision`, `headerRevision`, known `hosts`,
`availablePlaybooks`, and the active safe configuration. The status file has
mode 0600 and contains header names, not header values. A process exit and
`summary.json` establish final completion; a closed watcher's last status is
not a live process-health check.

For example, pause a scan, wait for `state: paused`, then replace its command file:

```json
{
  "action": "apply-resume",
  "commandId": "remove-host-and-adjust-limits",
  "expectedRevision": 0,
  "configuration": {
    "excludeHosts": ["skip.example"],
    "concurrency": 20,
    "perHostConcurrency": 20,
    "requestsPerSecond": 20,
    "playbooks": ["bypass.header.forwarded", "bypass.path.api_prefix"],
    "headers": ["User-Agent: Assessment-UA", "X-Test-Run: owned"],
    "removeHeaders": ["Authorization"],
    "userAgentMode": "disabled"
  }
}
```

Read back `revision: 1`, an empty `error`, and `lastCommandId` before treating the
edit as accepted. `apply` validates/applies and stays paused; `apply-resume`
also resumes. `expectedRevision` is required for either edit. Stale revisions,
unknown playbooks/fields, invalid limits and conflicting set/remove headers
are rejected atomically without resuming or sending traffic. Correct the command
file and retry with a fresh command ID and the current revision.

Configuration keys are partial replacements. Omitted fields retain their current
values. An included `headers`, `removeHeaders`, `excludeHosts` or `playbooks`
array replaces that entire list; an empty array clears it. Each `headers` entry
contains exactly one `Name: value` line. `userAgentMode` accepts `disabled`,
`synthetic` or `browser-like`; `userAgentSeed` changes the variation seed.
Obtain exact playbook IDs from `availablePlaybooks` in the status file. The
available inventory and original unsafe-method gates remain fixed for the run.

The original job file is not reread. Input destinations, request bodies/markers,
identifiers, protocol, proxy/TLS, timeout, retry-attempt count, calibration toggle
and state-changing opt-ins remain setup controls for a new run. Separate
`--traffic-max-in-flight` and `--traffic-max-rps` process ceilings remain active.
An exact retry-package replay keeps its saved inventory and adds no calibration
controls; explicit header/scope/limit edits still apply to its pending entries.

## Evidence and implementation

Schema-v1 JSONL gains optional `configurationRevision` and `headerRevision`. The latter groups comparison contexts across edits that change only scope/limits/checks. Credential-free
`configuration-N.json` files record accepted revisions alongside existing raw
request/response evidence. Sweep summaries report revised planned/completed
counts, skipped targets and the final configuration revision. Native result
metadata retains the revision and comparison intent used by each exchange.

`core.scan.LiveRun` owns immutable `RunConfiguration` snapshots, revision checks,
pause/drain state, exact-host admission and physical concurrency/rate limits.
`RequestTransport.sendManaged` and Burp's `RequestSender.sendManaged` place that
reservation together with outer traffic governors. Waiting on local pause or
limits holds no shared traffic slot. Pause time does not consume the network
request timeout. `ScanEngine` and `SweepWorkflow.Memory` retain completed work,
refresh header contexts and reuse controls for unchanged contexts. Replanning
keeps OOB payload identities stable. Large retained control bodies use private
run-owned temporary storage, removed when execution ends.
