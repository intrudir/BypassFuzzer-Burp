# Targeted authorization bypass

Use Bypass when one captured request is blocked or behaves differently across
roles and you want systematic request mutations.

```bash
python3 scripts/bypassfuzzer.py run bypass \
  --request blocked.raw \
  --target-origin https://app.example \
  --output evidence/bypass-001
```

Omitting `--families` runs all twelve families:

```text
header,path,verb,param,cookie,trailingdot,trailingslash,extension,contenttype,encoding,protocol,case
```

Use a comma-separated subset when the hypothesis is narrower. `--max-probes`
caps mutations and the planner distributes the cap across selected families
rather than exhausting one family first.

## Family intent

- `header`: proxy, routing, rewrite, and client-IP trust headers.
- `path`: path normalization and encoding payloads.
- `verb`: method changes, case variants, and method-override headers.
- `param` and `cookie`: debug parameters and existing-value mutations.
- `trailingdot`, `trailingslash`, and `extension`: alternate route shapes.
- `contenttype`: content-negotiation and parser selection.
- `encoding`: path and parameter encoding variants.
- `protocol`: alternate HTTP protocol selections.
- `case`: request-target case variants.

Add `--fuzz-existing-cookies` when cookie values already present in the request
are intended mutation points. Supply `--oob-domain` or `--oob-generator` to
include callback-dependent header payloads. A generator must print a hostname,
not JSON, and polling remains the caller’s responsibility.

## Validation

Start from the blocked baseline, then inspect each candidate's exact raw request
and response. Confirm that the response contains the protected resource or that
the protected action occurred on controlled data. Reproduce the smallest useful
mutation and rule out redirects, generic success pages, public fallbacks, cache
behavior, and intermediary normalization.
