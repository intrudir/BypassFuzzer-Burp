# Targeted bypass

## Sub-features

- Raw HTTP input keeps ordered duplicate headers and uses a separate `--target-origin` for routing.
- Any subset of the twelve stable attack-family IDs can run through the shared Bypass planner. The default inventory is uncapped; an explicit `--max-probes` bounds selected mutations.
- Explicit `--oob-domain` or an executable `--oob-generator` enables the shared out-of-band header inventory. The CLI does not create a Burp Collaborator client or accept a bare Collaborator-enable YAML flag.

## How to get to it (user POV)

Run `java -jar cli/build/libs/bypassfuzzer-cli.jar bypass --request request.raw --target-origin https://target.example --families header,path`.

## Driving it with the CLI helper

Run `verify.sh doctor <run-id>` followed by `verify.sh drive <run-id> bypass`. The lab blocks the original request and accepts a trusted `CF-Connecting-IP` mutation. Proof requires the raw emitted header, a `200` marker response, `LIKELY_BYPASS`, redacted stored authorization, and a rejected Collaborator YAML key.

## Gotchas

- `--target-origin` controls the socket/TLS destination; a mutated `Host` header does not silently reroute traffic.
- A status change is a triage signal, not a final authorization verdict. Inspect the stored request and response.
- Use only against targets for which active fuzzing is authorized.

Shared checks also have a [playbook/calibration recipe](playbooks.md). Bypass exposes Playbooks… with family shortcuts and a selected-playbook count, additional API prefixes and default-on Wildcard calibration. Candidate warnings preserve the original signal and retain a selectable Fallback control exchange.
