# Pause, edit and resume

## Sub-features

- All four attack commands accept plain control commands and atomic JSON edits.
- Status readback distinguishes pausing from fully paused and reports revisions
  without header values. Invalid/stale edits leave the previous config paused.
- Edits change exact-host exclusions, physical concurrency/rate caps, applicable
  playbooks and headers/UA for pending work. Completed probes are retained.
- Header edits refresh comparison/calibration controls; authenticated Sweep
  preserves credential stripping. Exclusions also apply to controls and retries.
- Evidence retains raw exchanges, additive configuration/header revisions and safe
  per-revision configuration files.

## How to get to it (user POV)

Run a mode with `--control-file control.txt`, write `pause`, and wait for
`control.txt.status.json` to report `state: paused`. Write `apply-resume` with
`expectedRevision` and a partial `configuration`, then read back the incremented
revision and empty error. Use IDs from `availablePlaybooks`. The complete JSON
contract and limitations are in [docs/LIVE-RUN-CONTROL.md](../../../../docs/LIVE-RUN-CONTROL.md).

## Driving it with the CLI helper

Run `verify.sh doctor <run-id>` then `verify.sh drive <run-id> editing`.
`helpers/editing_drive.py` drives a fresh packaged CLI process for each mode
against an owned loopback fixture. It proves an initial no-traffic pause, a
mid-run drained pause, rejected edits with no traffic, then scope/throttle/check
and header edits. It reads every referenced exchange, revisions and file modes.
Retain `assertions.json`, each mode's command/logs/status/readbacks/scan evidence,
`wire.json`, and `cleanup.json`. The driver terminates only its own processes and
server, including on assertion failure.

## Gotchas

- Use an unused evidence directory. Header values belong only in protected input
  and raw evidence; the status/history files expose names only.
- Preview sends no traffic. It cannot prove pause, drain or configuration effects.
- Exclusions match the socket origin, not a fuzzed Host header. They are exact
  normalized hostnames/IPs across all ports and apply only to the active run.
- Limits are upper bounds under adaptive backoff. Transport/input settings and
  unsafe-method opt-ins remain fixed. Exact replays retain their saved inventory.
- A closed process can leave its last status file behind; inspect its exit and
  final summary. Read mixed-revision results against their own controls.

Regression boundaries: retain queued failures across a header edit, recover them and
require an empty retry queue with the new headers and revision. Check distinct
same-URL credential/body seeds, two successive edited runs, late excluded-host
results, clearing configured credentials, and retained Retry-After cooldowns.
Native timeout fixtures must hold physical admission until a non-interruptible
Montoya call actually returns. Run `RunEditAdversarialRegressionTest` for these cases.

In native Sweep, require the visible retry queue to return to zero after edited
automatic recoveries. Stable work IDs must retain separate queued seeds while
removing the recovered item across header revisions.
