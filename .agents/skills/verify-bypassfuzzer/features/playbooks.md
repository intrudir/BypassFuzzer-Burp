# Shared playbooks and fallback controls

## Sub-features

- Bypass Playbooks… and Sweep Payload Families… embed `PlaybookSelectorPanel`, backed by immutable core `PlaybookSelection`. Family shortcuts, exact selected counts, previews and execution use that state; High signal and All selections remain separate.
- New entries cover structured Forwarded, Connection-nominated auth headers, trusted-path Referers, API insertion/version substitution and method case. Additional API prefixes and default-on Wildcard calibration are available with the selector.
- High signal Verb post/put requires Include state-changing methods in every Sweep mode. Full Bypass/All preserve existing Verb behavior.
- Shared calibration retains Original/authorized/target controls, warns Possible fallback or Calibration unavailable and exposes Fallback control in the native message viewers. All requests/responses and the original signal remain available. Sweep column order is unchanged.

## How to get to it (user POV)

Route an owned request through Repeater → Extensions → BypassFuzzer → Send to BypassFuzzer → Bypass. Use Playbooks… for exact selection. In Sweep use Payload Families… and its High Signal / All Bypass Families tabs; configure prefixes and calibration there. Preview before Start Fuzzing / Start Sweep.

## Driving it with verify-bypassfuzzer

Start with the artifact doctor and a disposable real Burp instance. Read `core/scan/BypassPlaybooks` and the exact artifact's CLI listing for IDs; do not copy an independent native inventory. The regression drive covers shared generators, selection, response comparison, native adapters and existing modes.

For live proof, use the owned loopback origin and actual stripping proxy in the CLI playbook helper. Confirm all five tabs and initial guidance. Verify catalog defaults, exact selected count and separate inventory selections. Preview must add zero fixture observations. Drive each of the six new entries through Start Fuzzing and inspect the accepted wire mutation. Run Sweep with exact API-prefix selection against the wildcard route; preserve the 403 Original, candidate signal and Possible fallback annotation, then select Fallback control and inspect its fresh sibling request and response. Preview High signal Verb with state-changing off/on and require post/put absent/present. Switch inventory and back to verify selection independence.

Require existing IDOR/URL Validation previews and live results as regressions. Verify Collaborator with a fresh native payload, owned self-callback and confirmed attributable DNS/HTTP polling; retain a native details screenshot and exclude the client secret. Rebuild/reload the final committed artifact and retain hashes/readiness. Stop only owned processes, delete temporary licensed settings/project copies and retain credential-free evidence.

## Gotchas

- Size the disposable display so tables and native editors are readable; verify the actual visible row before selecting it. A generated preview or model readback is not proof of the corresponding viewer.
- Selection actions and counts remain pinned while the playbook list scrolls. Assert the count before starting an exact-selection check.
- Controls remain visible even when unavailable; they do not overwrite Original or Auth verification. Clear Results must clear the fallback viewer too.
