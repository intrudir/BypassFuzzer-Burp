# BypassFuzzer CLI verification map

The CLI is a packaged Java command with four modes. Every mode writes streaming JSONL plus raw request/response evidence and a terminal summary. Build once with `helpers/verify.sh launch`, run `doctor` before every drive, and send automated traffic only to the helper's loopback lab unless the user explicitly authorizes another target.

## Features

- [Coverage Sweep](./sweep.md) covers URL-list scope and high-signal versus all-family planning.
- [Targeted bypass](./bypass.md) covers raw-request input and selectable bypass families.
- [IDOR / BOLA](./idor.md) covers identifier configuration, ordered baselines, and playbooks.
- [URL Validation](./url-validation.md) covers marker substitution, contexts, attacks, and encodings with explicit or generated OOB domains.

- [Runtime controls and retained results](./runtime-results.md) covers YAML/flag precedence, run control, traffic caps, evidence redaction, retained-result filters and exports.

## Proof conventions

- Use the packaged fat JAR, not an internal main-class shortcut.
- Retain the exact command, exit code, stdout/stderr, lab observations, summary, JSONL, and referenced raw messages.
- Exit code 2 is a preflight/configuration error. Once a scan starts, operational failures belong in `summary.json` and the CLI exits 0 so unattended evidence is retained.
- Flags override YAML, which overrides defaults. Use explicit `execution.oobDomain`/`execution.oobGenerator` settings; an unconfigured Collaborator boolean is rejected.
- Cleanup must retain the evidence directory.
