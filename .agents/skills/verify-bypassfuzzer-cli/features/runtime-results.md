# Runtime controls and retained results

## Sub-features

- OpenAPI preview and loopback sends prove managed-variable import through the packaged CLI.
- Version-1 YAML jobs are strict; explicit flags override YAML values, and input paths resolve relative to the job file.
- `--preview` prints planned requests without sending; `--header`, User-Agent, throttle, retry, protocol, timeout and proxy controls apply through the shared request/execution boundaries.
- `--control-file` accepts `pause`, `resume`, `stop`; traffic caps limit physical sends during a run.
- JSONL records reference retained raw requests/responses, with optional credential redaction, owner-only evidence permissions and a terminal summary.
- `results` filters retained evidence by status, length, content type, host, payload, signal and response text/regex; `--smart-repeats` limits repeated patterns.
- `results --format` supports `tsv`, `jsonl`, `hosts`, `payloads`; completed-host export uses summary metadata when available.

## How to get to it (user POV)

Use `java -jar cli/build/libs/bypassfuzzer-cli.jar <mode> --help` for runtime flags. After a run, use `results --input <evidence-dir> --show-status 200 --format jsonl` or select another export format.

## Driving it with the CLI helper

Run `verify.sh doctor <run-id>` then `verify.sh drive <run-id> runtime-results`. It reads packaged-CLI evidence through `results`, validates TSV/JSONL/host/payload exports, proves YAML/flag precedence with an offline preview, and pauses/resumes/stops a separate packaged scan against its own loopback server. Retain command transcripts, assertions, exported data, control summary and observed lab traffic.

## Gotchas

- Each CLI scan is isolated. Dashboard-style limits apply within that process; Burp's extension-wide registry and UI actions are host-specific.
- Filtering changes exported visibility, not retained source evidence. Review raw responses before declaring a finding.
- Protocol framing and the broader shared runtime combinations remain covered by the existing CLI/transport regression tests; one loopback drive does not prove arbitrary target behavior.

Playbook/calibration metadata remains additive to schema-v1 JSONL. Readback retains it; the repository-owned operating helper separates WILDCARD controls from baselines and prints warnings and safe control references without altering the original signal. See [playbooks.md](playbooks.md).

Calibration controls remain in raw evidence. `results` hides WILDCARD rows by default; `--show-calibration` includes them in the filtered view/export. They bypass Smart repeat suppression and do not consume candidate slots; explicit manual filters still apply. Preserve Original / Authorized / Target, legacy rows lacking role metadata and unknown future roles. The native Show calibration requests checkbox follows the same semantics. Protocol-labeled controls distinguish an actual empty 404 from an unavailable forced protocol exchange.

Run the [boundary drive](boundaries.md) for same-file/alias export rejection, strict TLS identity and headerless response limits. An export collision must exit 2 before opening the sink and leave the input byte-identical.

For runtime scope, throttle, playbook and header changes, follow [Pause, edit and resume](editing.md). Initial setup controls remain separate from the active revision.
