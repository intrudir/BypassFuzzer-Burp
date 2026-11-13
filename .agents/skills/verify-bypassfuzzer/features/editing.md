# Pause, edit and resume

## Sub-features

- `run-edit` opens the same **Edit run…** dialog in Bypass, Sweep, IDOR and
  URL Validation, including active manual retry passes.
- `run-drain` distinguishes Pausing… from Paused and enables Apply & Resume only
  after physical sends drain. Keep paused applies no edits.
- `run-configuration` edits Scope, Throttle, Playbooks and Headers as one immutable
  revision. Invalid edits leave the old config paused; the button shows rN after
  accepted changes.
- `run-continuation` replans pending work without replaying completed probes;
  new headers refresh matching controls. Scope applies to all outgoing work.

## How to get to it (user POV)

Start any attack, choose Pause then Edit run…, or choose Edit run… directly.
Use Scope checkboxes for exclusions; Throttle for concurrency and rate ceilings;
Playbooks for the mode's exact inventory; Headers for configured lines, removals
and UA variation. Choose Apply & Resume or Keep paused. IDOR preserves its
existing confirmation when a dangerous playbook is newly enabled.

## Driving it with verify-bypassfuzzer

Run the artifact doctor, then `verify.sh drive <run-id> editing` for shared
pause/drain/physical-boundary/manual-retry regressions. Also run the packaged
CLI editing drive from the neighboring skill.

In one disposable real Burp project, exercise all four workspaces against owned
loopback URLs. Pause during actual traffic, require the drained count and no new
wire exchanges, change headers/limits and enable a previously disabled check,
then Apply & Resume. In Sweep exclude one of two hosts and prove no subsequent
probe, control or retry reaches it. Reject an invalid per-host/total limit pair
and prove the revision and traffic remain unchanged. Repeat local editing under
Dashboard global pause, then lift only the global overlay. Read actual result
metadata/viewers and confirm fresh Original/Authorized/Target/Fallback controls
for the new header context. Check all five tabs and targeted empty states; retain
screenshots, the exact loaded JAR hash, traffic and credential-free readbacks.
For OOB changes, require the skill's real Collaborator callback/poll proof.

## Gotchas

- This edits the active run. Initial setup controls are unchanged for the next
  scan; Edit run… shows the active revision. Completed results stay visible.
- Scope exclusions do not change Burp project scope or socket destinations.
- Dashboard global pause remains independent of local pause/resume. Network
  timeout starts after admission, so waiting behind either gate is not a failure.
- Original credentials stay absent from authenticated Sweep's anonymous mutation
  and calibration contexts. Apply header edits before credential stripping.
- Exact manual retry inventories only replay saved requests; filtering checks
  does not generate new seeds. Input/protocol/unsafe-method setup remains fixed.
- Follow [docs/LIVE-RUN-CONTROL.md](../../../../docs/LIVE-RUN-CONTROL.md) for the
  shared semantics and CLI command/status contract.

Regression boundaries: retain queued failures across a header edit, recover them and
require an empty retry queue with the new headers and revision. Check distinct
same-URL credential/body seeds, two successive edited runs, late excluded-host
results, clearing configured credentials, and retained Retry-After cooldowns.
Native timeout fixtures must hold physical admission until a non-interruptible
Montoya call actually returns. Run `RunEditAdversarialRegressionTest` for these cases.
