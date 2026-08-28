# Dashboard and global control

Dashboard is BypassFuzzer's master view for every open Sweep, Bypass, IDOR, and URL Validation activity, including global traffic safety and per-activity controls.

## Sub-features

- `dashboard-inventory` lists each open activity with mode, target, state, progress, its displayed `Sent` metric, and actions.
- `dashboard-open` returns to the selected activity through its `Open` table action.
- `dashboard-row-control` pauses/resumes or stops one active activity.
- `dashboard-global-pause` uses `Pause All` and `Resume All` as a global request-admission overlay without clearing local pauses.
- `dashboard-stop-all` stops active scans and retry passes after confirmation while retaining tabs and results.
- `dashboard-limits` enables per-host requests/second and total in-flight caps for this Burp launch.
- `dashboard-update` shows the installed and available versions in a suite-wide banner when the update check finds a newer release, and lets the user dismiss the notice.

## How to get to it (user POV)

- Choose the suite-level `BypassFuzzer` tab, then choose `Dashboard`.
- From an activity tab, return to the top-level `Dashboard` tab.
- Use `Open`, `Pause`/`Resume`, or `Stop` in an activity row.
- Use `Pause All`, `Resume All`, or `Stop All` above the table.
- In `Extension-wide traffic safety`, select `Enable global limits` and edit `Max req/s per host` or `Max total in-flight`.
- When an update notice appears above the top-level tabs, review its current/latest versions and use `Dismiss` to hide it.

## Driving it with verify-bypassfuzzer

Preconditions:

- The launch and doctor commands passed for the current `RUN_ID`.
- A visual row-action pass needs at least one activity created through Sweep or `Send to BypassFuzzer`.
- A manual `Stop All` pass uses a disposable scan because stopping is not reversible.

- **Automated control proof.** Run `./.agents/skills/verify-bypassfuzzer/helpers/verify.sh drive "$RUN_ID" dashboard`. The Swing harness requires the five top-level tabs, exercises an activity row's `Open`, `Pause`, and `Stop` actions, verifies global limits start disabled at suggested values of 10 req/s per host and 10 in-flight, and injects a synthetic newer-version result to verify and dismiss the update banner without contacting the external manifest.
- **Open an activity.** In Burp, choose `Open` in its Dashboard row. The corresponding top-level mode and nested request tab become selected.
- **Pause globally.** Choose `Pause All`. The traffic summary begins with `GLOBAL PAUSE`, active rows read `Paused globally`, and already-sent requests may still finish.
- **Preserve local pause.** Pause one row locally, choose `Pause All`, then `Resume All`. The global pause clears while the locally paused row remains paused.
- **Apply limits.** Select `Enable global limits`, set both spinners, and observe the traffic summary show `<rate> req/s per host` and `<count> max in-flight`. Reopen Dashboard after activity to confirm the values remain for this Burp launch.
- **Proof.** Retain `dashboard/swing-controls.log`, `dashboard/test-results/test/`, and manual before/after screenshots when layout or Burp rendering changed.

## Gotchas

- `Resume All` removes only the global overlay; it intentionally does not resume sessions paused at the row or tab level.
- `Stop All` requires confirmation and keeps tabs/results open; disappearance of a row is not the expected result.
- Limits reset whenever Burp restarts and start disabled, so persistence across launches is not expected.
- Existing responses can arrive after pause because Pause blocks new sends, not requests already in flight.
- The update check is asynchronous. No banner is expected when the installed version is current, the manifest URL is disabled, or the check fails; failures are logged without blocking the extension.
