# Shared playbooks and fallback calibration

## Sub-features

- `core/scan/BypassPlaybooks`, `PlaybookSelection` and `PlaybookOptions` own stable IDs, family shortcuts, defaults and supported inventories. Existing checks remain catalog entries alongside six additions; High signal schedules bounded representatives fairly and All payloads remains uncapped.
- `--list-playbooks`, exact `--playbooks`, repeatable `--api-prefix`, and `--[no-]wildcard-calibration` work in Bypass/Sweep; mode YAML equivalents preserve flag precedence. Invalid or conflicting selections fail before traffic.
- Structured Forwarded, hop-by-hop auth, trusted Referers, API prefixes, version swaps and method case preserve unrelated request context. Hop probes run only in HTTP/1, once in BOTH. High signal post/put requires state-changing opt-in.
- Shared `WildcardCalibration` compares status, normalized media type and length within 50 bytes. HEAD requires wire Content-Length; Netty aggregation cannot invent a usable value. Failed/throttled controls remain evidence and do not abort mutations.
- Optional schema-v1 playbook/control/calibration fields retain original signals and raw-message references. `WILDCARD` controls cannot replace Original/authorized/target baselines. Exact retry files accept optional metadata and inject no controls.

## How to get to it (user POV)

Run `bypass --list-playbooks` or `sweep --payload-set high-signal --list-playbooks`, select IDs with `--playbooks`, then preview or run against the established scope. Use `results --input <run> --format jsonl` to retain annotation metadata in readback.

## Driving it with the CLI helper

Run `helpers/verify.sh doctor <run-id>` then `helpers/verify.sh drive <run-id> playbooks`. `helpers/playbooks_drive.py` launches an owned origin and a second loopback HTTP proxy that strips Connection-nominated headers before forwarding. It drives the packaged JAR through listing, every new mechanism, both inventories, BOTH hop accounting, state-changing gates, GET/HEAD calibration matches/nonmatches/unavailable controls, disabled calibration, credential stripping, YAML/flag precedence, traffic-free previews and invalid preflight, plus evidence readback. Retain commands, responses, raw-message references, fixture observations and the exact JAR hash. Failed iterations retain evidence; all owned servers close in finally.

## Gotchas

- Possible fallback is an annotation, never a demotion or filter. An unavailable control is not a nonmatch.
- HTTP/1-only probes are skipped under forced HTTP/2; AUTO selects HTTP/1 for them.
- Synthetic fixture credentials are not live identities. Native Collaborator polling requires Burp Professional and a separate disposable-project proof.
