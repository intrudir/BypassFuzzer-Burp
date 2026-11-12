# Shared playbooks and wildcard calibration

Use this reference when selecting Bypass/Sweep checks or interpreting fallback warnings. Obtain current IDs from the installed artifact:

```sh
python3 scripts/bypassfuzzer.py run bypass --list-playbooks
python3 scripts/bypassfuzzer.py run sweep --payload-set high-signal --list-playbooks
```

Omitted playbooks use defaults within selected families. `--playbooks ID,ID` selects exact entries. Conflicting explicit family restrictions fail before traffic. Add repeatable `--api-prefix /private-api` values as absolute paths without origin, query or fragment. The mode's YAML section accepts `playbooks`, `apiPrefixes`, `wildcardCalibration`; explicit CLI flags override YAML.

High signal distributes its cap across playbooks and has a Verb group. Its post/put probes require `--include-state-changing`. Full Bypass and All payloads retain their usual Verb behavior. Hop-by-hop authentication requires HTTP/1: AUTO selects it, forced HTTP/2 reports unsupported checks, and BOTH sends those probes once in its HTTP/1 pass.

Calibration defaults on for GET/HEAD; `--no-wildcard-calibration` disables it. Preview identifies fresh runtime controls without sending them. Exact retry replays add no controls. Authenticated Sweep calibrates the credential-stripped context used by mutations.

Keep Possible fallback candidates visible. Matching status, normalized media type and length within 50 bytes adds the warning; HEAD needs comparable wire Content-Length. Failed, missing or throttled controls yield Calibration unavailable. Neither warning changes the signal. Inspect `calibration.controlRequestRef` / `controlResponseRef` and compare the protected resource with the Original/authorized/target baseline. `WILDCARD` controls remain separate in the triage helper and must never replace those baselines.
