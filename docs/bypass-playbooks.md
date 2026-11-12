# Shared bypass playbooks and fallback calibration

`core/scan/BypassPlaybooks` is the authoritative catalog for Bypass and both Sweep inventories. Family controls select groups of playbooks; exact IDs select only those entries. Existing family names remain valid. All playbooks default on within their selected family. High signal takes bounded representatives in round-robin playbook order before its cap; All payloads stays complete and uncapped.

| Added ID | Wire changes |
| --- | --- |
| `bypass.header.forwarded` | `Forwarded: for=` and `For=`, including quoted bracketed IPv6 |
| `bypass.header.hop_by_hop_auth` | Connection nominations with captured and sentinel Authorization, Cookie, API-key and token headers |
| `bypass.header.trusted_referer` | Same-origin `/admin`, `/dashboard`, `/internal` Referers |
| `bypass.path.api_prefix` | `/v2`, `/v3`, `/api/v1`, `/api/v2`, `/api`, plus additional operator prefixes |
| `bypass.path.api_version_swap` | Alternate versions at each existing `vN` path segment |
| `bypass.verb.method_case` | Existing method-case variants plus lowercase get/post/put/head/options |

Hop-by-hop probes require HTTP/1. AUTO uses HTTP/1 for them, forced HTTP/2 skips them with an unsupported message, and BOTH includes them once in its HTTP/1 pass. High signal's new Verb group requires Include state-changing methods for post/put. Targeted Bypass and All payloads retain full Verb-family behavior.

## Select and preview

In Burp, open Bypass → Playbooks… or Sweep → Payload Families… . Both use the same catalog-backed selector with family shortcuts, an exact count and independent Sweep inventory selections. Additional API prefixes and Wildcard calibration are available alongside those controls. Sweep keeps its Payload, Host, Family, Signal column order.

```sh
java -jar cli/build/libs/bypassfuzzer-cli.jar bypass --list-playbooks
java -jar cli/build/libs/bypassfuzzer-cli.jar sweep --payload-set high-signal --list-playbooks
java -jar cli/build/libs/bypassfuzzer-cli.jar bypass --request blocked.raw   --target-origin https://app.example --playbooks bypass.path.api_prefix   --api-prefix /private-api --preview
```

`--playbooks` selects exact entries; a conflicting explicit `--families` restriction fails before traffic. API prefixes are repeatable absolute path prefixes without origin, query, fragment or whitespace. CLI flags override YAML. The `bypass` and `sweep` sections accept `playbooks`, `apiPrefixes` and `wildcardCalibration`:

```yaml
schemaVersion: 1
bypass:
  playbooks: [bypass.path.api_prefix, bypass.path.api_version_swap]
  apiPrefixes: [/private-api]
  wildcardCalibration: true
```

Previews send no traffic. They identify fresh runtime-generated calibration controls and HTTP/1-only probes. Exact retry packages replay retained requests without injecting controls.

## Interpret calibration

Wildcard calibration defaults on for GET/HEAD seeds. `--no-wildcard-calibration` or the Burp checkbox turns it off. One fresh sibling-path control is generated per seed/protocol/credential context, preserving origin, query, body and header policy. Controls use the same transport, governor and retry accounting as normal traffic. Authenticated Sweep calibrates its credential-stripped context.

A matching status, normalized media type and response length within 50 bytes adds **Possible fallback**. HEAD requires usable Content-Length values on both responses; missing or invalid values mean calibration unavailable. Failed or throttled controls stay visible and do not abort mutations. Calibration never changes the original signal, candidate classification or visibility. Inspect the selectable Fallback control exchange before accepting a candidate.

Evidence remains schema version 1. Additive fields include `playbookId`, `controlRole` and `calibration` with assessment, annotation and control raw-message references. `WILDCARD` controls are separate from Original, authorized and target baselines. Retry files accept optional playbook/control metadata while older entries remain readable.

## Repeatable proof

Run the full Gradle suite, then `./.agents/skills/verify-bypassfuzzer-cli/helpers/verify.sh drive <run-id> playbooks`. The packaged-CLI fixture verifies every addition, both Sweep inventories, real two-hop header stripping, flags/YAML, previews, preflight rejection, calibration matches/nonmatches/unavailable controls, preserved signals, credentials and evidence readback. Native verification additionally requires a disposable real Burp project for all five tabs, empty states, selection/previews, fallback viewers, gating and Collaborator callbacks.
