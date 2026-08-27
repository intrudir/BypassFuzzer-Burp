# Coverage Sweep

## Sub-features

- URL lists, raw requests, request manifests, OpenAPI, Postman, and retry packages define scope.
- `high-signal` uses the bounded Sweep corpus; `all` selects shared bypass families.
- State-changing OpenAPI/Postman operations remain off unless explicitly enabled.

## How to get to it (user POV)

Run `java -jar cli/build/libs/bypassfuzzer-cli.jar sweep --help`, then choose exactly one input source and a payload set.

## Driving it with the CLI helper

Run `verify.sh doctor <run-id>` followed by `verify.sh drive <run-id> sweep`. The drive supplies a one-line loopback URL list, runs high-signal probes, and requires a completed summary, baseline plus mutations, zero transport errors, redacted evidence, and real lab requests.

## Gotchas

- Exactly one input source is required.
- `--max-probes` applies per input; the baseline is additional.
- Imported API operations that can change state require `--include-state-changing` and explicit target authorization.
