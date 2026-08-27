# IDOR / BOLA

## Sub-features

- Exact authorized and target identifiers are required.
- The authorized control and target-denied baseline run before context-aware playbooks.
- Path, query, body, and hybrid playbook IDs remain stable in evidence.

## How to get to it (user POV)

Run `java -jar cli/build/libs/bypassfuzzer-cli.jar idor --request request.raw --target-origin https://target.example --authorized-id alice --target-id bob`.

## Driving it with the CLI helper

Run `verify.sh doctor <run-id>` followed by `verify.sh drive <run-id> idor`. Proof requires `idor.baseline.control` and `idor.baseline.target` as the first two records, followed by at least one playbook request, with all referenced raw evidence present.

## Gotchas

- Identifiers are exact literals; an absent authorized identifier is a preflight error.
- Similarity to the authorized response is evidence to review, not an automatic access-control verdict.
- Baseline evidence must be interpreted before playbook results.
