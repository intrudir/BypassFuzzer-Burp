# Coverage Sweep

## Sub-features

- URL lists, raw requests, request manifests, OpenAPI, Postman, and retry packages define scope.
- OpenAPI uses the shared Burp parameter policies and managed variables. Default `required-variables` blocks unresolved values for enabled operations; `--openapi-variable NAME=VALUE` overrides per name, `--openapi-parameter-policy` selects the shared policy, and `--openapi-fill-examples` fills only blank values from unambiguous shared suggestions. YAML equivalents are under `input`; local spec paths resolve relative to the job file.
- `high-signal` uses the bounded Sweep corpus; `all` selects shared bypass families.
- `--sweep-mode authenticated` uses the shared anonymous-control/public-endpoint workflow with configurable credential headers/cookies; endpoint dedupe, static-asset exclusion, excluded hosts and custom Host ports are configurable.
- Exact retry packages retain saved mutations and retry metadata; they do not regenerate a new catalog.
- State-changing OpenAPI/Postman operations remain off unless explicitly enabled.

## How to get to it (user POV)

Run `java -jar cli/build/libs/bypassfuzzer-cli.jar sweep --help`, then choose exactly one input source and a payload set.

## Driving it with the CLI helper

Run `verify.sh doctor <run-id>` followed by `verify.sh drive <run-id> sweep`. The Sweep drive supplies a one-line loopback URL list, runs high-signal probes, and requires a completed summary, baseline plus mutations, zero transport errors, redacted evidence, and real lab requests.

For the OpenAPI path, also run `verify.sh drive <run-id> runtime-results`; it previews and sends an OpenAPI import with explicit variables against its owned lab. `CliOpenApiParityTest` compares all policy variants with the shared importer, proves YAML overrides and preflight failures, and checks enabled-operation variables on the wire.

## Gotchas

- Exactly one input source is required.
- High Signal uses the master's control accounting plus enabled Host probes. `all` is uncapped and rejects `--max-probes`. Retry packages replay exact saved mutations.
- Imported API operations that can change state require `--include-state-changing` and explicit target authorization.
