# URL Validation

## Sub-features

- A literal marker identifies injection positions in the raw request.
- Contexts, attack families, and encodings select parser/allow-list payloads.
- An explicit attacker host is required; Collaborator is absent from this CLI surface.

## How to get to it (user POV)

Run `java -jar cli/build/libs/bypassfuzzer-cli.jar url-validation --request request.raw --target-origin https://target.example --allowed-host trusted.example --attacker-host attacker.example`.

## Driving it with the CLI helper

Run `verify.sh doctor <run-id>` followed by `verify.sh drive <run-id> url-validation`. The drive requires a baseline containing `{INJECT}`, mutation evidence in which the marker was replaced, real loopback responses, and rejection of a Collaborator YAML key.

## Gotchas

- The marker must be present in the active raw request.
- Stored payload evidence reflects the exact contexts, attacks, encodings, hosts, and headers selected for that run.
- Raw CR/LF payloads that cannot cross the safe request-model boundary are excluded; encoded variants remain.
