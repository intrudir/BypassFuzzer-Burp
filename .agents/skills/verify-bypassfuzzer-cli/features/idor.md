# IDOR / BOLA

## Sub-features

- Exact authorized and target identifiers are required; repeated authorized values need `--id-location`.
- The authorized control and target baseline run before context-aware playbooks. A 2xx target baseline is marked `TARGET_BASELINE_2XX_REVIEW` and still allows mutations; status alone does not prove direct access.
- Path, query, body, and hybrid playbook IDs remain stable in evidence.
- The response-guided family is enabled by default and discovers exact identifier values in baseline JSON, then tests authorized-path body assignment and target-path/body conflicts through the shared planner.
- The paired-control separator family is enabled by default, sends `id1%0Aid2` and its reverse first for URL IDs, and reports planned/eligible counts in offline preview.
- Every applicable probe from enabled IDOR playbooks is planned without a numeric cap. `--max-probes` and YAML `execution.maxProbes` are rejected for IDOR so shared settings cannot truncate coverage silently.
- DANGEROUS identifier-guessing families are off by default: numeric pivots, special values (`0`, `1`, `-1`), JSON edge cases, canonical formats, and truncated variants. Explicit `--families` or YAML selection is required, and the CLI warns on stderr.

## How to get to it (user POV)

Run `java -jar cli/build/libs/bypassfuzzer-cli.jar idor --request request.raw --target-origin https://target.example --authorized-id alice --target-id bob --id-location path:2`. Use `--preview` to inspect the plan without sending.

## Driving it with the CLI helper

Run `verify.sh doctor <run-id>` followed by `verify.sh drive <run-id> idor`. Proof requires `idor.baseline.control` and `idor.baseline.target` as the first two records, followed by at least one playbook request, with all referenced raw evidence present.

## Gotchas

- Identifiers are exact literals; an absent authorized identifier is a preflight error.
- Similarity to the authorized response is evidence to review, not an automatic access-control verdict.
- Baseline evidence must be interpreted before playbook results.
- `--baseline-response` supplies a saved raw HTTP response for offline preview only; live baseline responses determine requests sent during a scan. A write response that echoes an injected field remains a candidate for manual readback.
- With synthetic numeric ID requests, the default preview must omit nearby IDs and standalone `0`, `1`, `-1` values; an explicit dangerous family selection must include its applicable variants and print DANGEROUS on stderr.
- With a synthetic path ID request, the default preview must include both LF directions and a separator coverage count. Selected auto/HTTP/2 headers and cookie values must report skipped control probes; `--protocol http1` may emit inline-tab header probes only.
