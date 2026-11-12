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
