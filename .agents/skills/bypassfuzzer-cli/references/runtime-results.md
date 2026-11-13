# Runtime control and retained results

All four scan modes accept `--preview` to print planned wire requests without
sending target traffic or creating evidence. Runtime defaults and YAML precedence
are in [common.md](common.md). Preview can allocate OOB tokens when configured.

## Dashboard counterparts

`--traffic-max-in-flight N` limits physical requests across the CLI process;
`--traffic-max-rps N` limits per-host request rate. These are separate from
planner concurrency. `--control-file PATH` reads `pause`, `resume`, or `stop`
during a running scan. Write a command to that file to control the process;
inspect its final summary after stopping. Burp's global activity registry and
native editor actions remain host-specific; each CLI process owns its limits.

`--posture conservative`, throttle codes, retry attempts, and pause mode control
response-driven backoff. Retries remain individual evidence rows. In YAML these
controls live under `execution` (`controlFile`, `trafficMaxInFlight`,
`trafficMaxRps`, `posture`, `pauseMode`, `fixedPauseMillis`).

## Filter and export

The helper supports the native fifth command, `results`, unchanged:

```bash
python3 scripts/bypassfuzzer.py run results --input evidence/run-001 \
  --show-status 200 --response-contains 'protected-marker' --format jsonl

python3 scripts/bypassfuzzer.py run results --input evidence/run-001 \
  --format payloads --output selected-payloads.txt
```

`--input` accepts an evidence directory or its `results.jsonl`. Filters cover
show/hide status and length, min/max length, content type, host, payload, signal,
and response text. `--signal-regex`, `--response-regex`, and
`--invert-response-match` control matching. `--smart-repeats N` retains the first
N rows per status/length/content-type pattern.

Formats are `tsv` (default), `jsonl`, `hosts`, and `payloads`. Filtering affects
exports, leaving original evidence intact. When a summary has `completedHosts`,
`hosts` exports that list directly and bypasses row filters. Native result errors
propagate their exit code; the scan-specific “exit 0 after starting” contract does
not establish successful result export.

For baseline/body comparisons and evidence integrity checks, use the helper's
separate `triage` action described in [evidence.md](evidence.md). No export signal
proves a vulnerability by itself.

## Calibration rows

`results` hides standalone calibration controls by default. Add `--show-calibration` to include them in TSV/JSONL or other filtered exports. Raw scan `results.jsonl`, request/response files and counters retain every exchange. Smart repeat filtering reserves its slots for ordinary results; explicitly shown controls remain subject to manual status/text filters. Baseline roles stay visible. Calibration payload labels include the requested protocol, since an HTTP/1 replay can return 404 while a forced HTTP/2 attempt has no response.

`results --output` must differ from its input evidence file, including hard-link and symbolic-link aliases; collisions fail with exit 2 without truncation. Recovered Sweep responses get newly computed signals and calibration warnings from their retained baselines, so include retry records when triaging by signal.

## Edit pending work

The control file also accepts JSON `apply` and `apply-resume` commands. First
write `pause` and wait for `<control-file>.status.json` to show `state: paused`
and `inFlight: 0`. Read its `revision`, `hosts`, and `availablePlaybooks`.
Send an edit with that `expectedRevision`; read back the incremented revision
and an empty `error`. Invalid edits leave the old configuration paused.

`configuration` supports `excludeHosts`, `concurrency`, `perHostConcurrency`,
`requestsPerSecond`, `playbooks`, `headers`, `removeHeaders`, `userAgentMode`
and `userAgentSeed`. Fields are partial replacements; supplied arrays replace
whole lists. Header entries contain one `Name: value` line. Protect this file
like a raw authenticated request, and write it atomically with a sibling rename.
The status and `configuration-N.json` evidence files contain header names only.

Playbook IDs come from the status inventory: Bypass/Sweep catalog IDs, existing
`idor.*` families, or `url.context.<ENUM>` / `url.attack.<ENUM>`. Adding a check
plans applicable unsent work; completed probes retain their evidence and are not
repeated. Exclusions use the socket host across all ports and cover controls and
retries. Header edits refresh comparison/calibration contexts; authenticated
Sweep still strips selected credentials before anonymous traffic.

Input/transport settings, IDs/markers, retry counts, calibration and unsafe-method
opt-ins remain fixed for a run. Exact retry packages retain their saved inventory
and add no calibration controls. Separate process traffic ceilings still apply.
Read mixed-revision results against their own controls; a closed process's last
status is not evidence it is still running. Full examples and semantics are in
[the repository contract](../../../../docs/LIVE-RUN-CONTROL.md).
