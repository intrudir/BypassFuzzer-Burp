# BypassFuzzer workbench design QA

final result: passed

Scope: the user selected displayed option 1, requested its style across all five production Swing tabs, and corrected Sweep's table to put the payload before the host and family. This is a native extension rework, not a web prototype or a pixel-exact recreation of generated sample data.

## Visual evidence

- Source visual truth: `artifacts/verification/workbench/selected-reference.png` (1487 × 1058 pixels).
- Implementation: `artifacts/verification/workbench/sweep.png` (1440 × 1024 pixels).
- Full comparison: `artifacts/verification/workbench/comparison-sweep.png`.
- Focused comparison of table hierarchy, typography and evidence: `artifacts/verification/workbench/comparison-details.png`.
- Additional tabs: `dashboard.png`, `bypass.png`, `idor.png`, `url-validation.png` in that same evidence directory.
- Additional states: `sweep-filters.png`, `bypass-options.png`, `idor-configuration.png`, `url-validation-configuration.png`, `sweep-1280.png`.

Native viewport: 1440 × 1024, with a second 1280 × 800 capture. Density is one captured pixel per desktop pixel; CSS dimensions do not apply. The reference's 40-pixel Burp host tool strip is excluded in the comparison, then scaled proportionally and padded to the capture dimensions. Native captures contain extension-owned content only. No pixel-level fidelity claims are made from the normalization.

State: six deterministic fixture results, selected probe, dark theme. The reference contains an illustrative finished run; the implementation deliberately records zero real HTTP requests and disables actions whose prerequisites are absent. Fixture counts, result values, host strip and enabled states therefore differ. Comparisons assess the approved style and actual workflow, not fabricated run data.

## Comparison history

1. Initial native captures (`sweep-before.png`, `url-configuration-before.png`) exposed P2 issues: bright boxed table headers; dark text in nested titled borders; an empty candidate table consuming evidence space; tight action and column layouts at smaller sizes.
2. Fixed table headers and nested border styling; collapsed the candidate table when empty; moved manual filters into a drawer; separated results heading and actions; moved Sweep export/clear actions to results; enforced readable table column minimums with horizontal scrolling; kept explicit keyboard focus indicators.
3. Recaptured all tabs and configuration dialogs. Full and focused comparisons show those issues resolved. The final captures also give request/response pairs dedicated resizable evidence panes and preserve original/auth-verification exchanges in separate tabs. No actionable P0/P1/P2 findings remain in the extension-owned surfaces inspected.

## Required fidelity surfaces

- **Fonts and typography:** native sans serif 14px controls, 19–24px headings, 13px monospace payloads/evidence. Readable hierarchy; long data values remain accessible through table scrolling and evidence. Desktop fonts differ from generated-image lettering by design.
- **Spacing and layout:** compact controls, 310px scrollable Sweep rail, lightweight section rules, consistent result headers, resizable request/response pairs. Configuration and filter drawers can be reopened. Native controls and the complete existing feature set take precedence over the mock's simplified inventory.
- **Colors and tokens:** charcoal `#202224`, editor surface `#191B1D`, control surface `#2B2E31`, separators `#3B3E41`, orange `#F28B50`, readable muted text, green HTTP success statuses. Styling is scoped to the extension and does not change Burp's UIManager defaults.
- **Image quality/assets:** no raster illustrations or custom icon assets exist in the selected design. Standard Swing controls are used. Screenshots are real desktop captures, not rasterized mockups placed over controls.
- **Copy/content:** production mode names and control behavior remain available. Sweep is `# / Payload / Host / Family / Signal / Status / Length / Content-Type`, with full payload metadata and original target available in the evidence view/tooltip. Host comes from the request transport destination, with target-URL fallback; fuzzed Host-header text is not treated as the network destination.

## Verification

Command on a host with Xvfb:

```sh
xvfb-run -a -s '-screen 0 1600x1200x24' ./gradlew :test :previewWorkbench :shadowJar :core:test --no-daemon
```

- 323 Burp tests and 90 shared-core tests passed; zero failures/errors.
- Exercised all five tab selections, Sweep source modes, configuration collapse/reopen, manual-filter drawer, Bypass run options and IDOR/URL configuration dialogs.
- Verified that existing request/session controls, filtering, retry and evidence behavior pass the regression tests.
- Added a theme boundary test proving that global UIManager defaults and native editor components remain untouched while dynamically inserted components receive the extension theme.
- `git diff --check` passed.

## Practical limits and follow-up polish

The original preview ran the production Swing panels under Xvfb with Montoya editors replaced by text fixtures and sent no scan traffic. The subsequent native Burp pass below covers the real editor and host integration. Production editor internals retain Burp's own settings. Browser checks do not apply to this native application.

P3: the detailed existing run-summary strings can truncate in smaller windows; their counters and underlying run behavior are unchanged. Long identifiers and payloads can require horizontal scrolling.

## Implementation checklist

- [x] Apply selected palette and control styling across all five tabs and primary configuration dialogs.
- [x] Implement the user's corrected Sweep column order.
- [x] Preserve the existing scan engine, retry behavior and native evidence editors.
- [x] Capture and compare the real Swing surfaces at two window sizes.
- [x] Run the existing tests and build the extension JAR.

## Follow-up: request-tab empty states

The user's fresh-load screenshot showed a blank targeted tab. Bypass, IDOR and URL Validation now show centered guidance with the exact existing context-menu path: `Right-click any request and choose` followed by `Send to BypassFuzzer → <mode>`.

Evidence: `artifacts/verification/workbench/bypass-empty.png`, `idor-empty.png`, and `url-validation-empty.png` (1440 × 1024 native captures). Inspected all three for text, alignment, readable contrast and consistency with the workbench style. The populated tabs and five-tab preview still work. No new assets or controls are introduced.

Eight main-tab regression tests passed, including a new lifecycle check across all three modes: show the message initially, hide it when a request arrives, keep it hidden while any session remains, and restore it when the last session closes. The offline desktop preview and JAR build also passed. This follow-up ran the targeted tests; the 413-test result above records the earlier full rework verification.


## Native Burp verification — 2026-11-12

Loaded the production JAR into Burp Suite Professional 2026.9-53998 using a
run-owned developer extension that delegates to `BurpExtender`. Montoya, message
editors, context menus, HTTP transport and Collaborator were real. The disposable
project used a private display, data directory, preferences and temporary files.
Existing license settings were reused with the user's explicit authorization.

Evidence is under `artifacts/verification/native-burp-20261112/`, including
screenshots, actual Swing component snapshots, copied TSV results, loopback
request observations, source/revision metadata and regression XML. The temporary
driver sources are retained there for reproduction; they are not a supported
repository GUI launcher.

| Surface | Native verification |
| --- | --- |
| Dashboard | All four activity types visible; global limits and Pause All/Resume All exercised; only Sweep remains after targeted sessions close. |
| Sweep | Imported an owned loopback URL through the file picker; previewed 140 exact probes; completed 140 results; exercised pause/resume; copied and read back TSV; checked Payload/Host/Family column order and paired native editors. |
| Bypass | Routed through Repeater's Extensions → BypassFuzzer → Send to BypassFuzzer menu; completed 1,233 Header-family results, including 16 expected successful fixture responses; read back the TSV export. |
| IDOR | Routed through the actual menu; entered controlled IDs 100/200; completed 214 baseline/playbook results and inspected native evidence. |
| URL Validation | Routed a literal `{INJECT}` request; configured native Collaborator payloads; completed 184 probes, including 38 expected successful fixture responses; inspected substituted wire requests. |
| Empty states | Each targeted mode showed the correct route initially, hid it with two sessions, kept it hidden after one close, and restored it after the last confirmed close. |
| Collaborator | Production default payload helper and a separate native client each received HTTP 200 for direct self-test callbacks. The client polled DNS, DNS and HTTP interactions; Burp's Collaborator UI also displayed attributable DNS/HTTP events and the raw callback request. |

The pass found and fixed three native UI issues: message viewers needed more
reading space; divider initialization had to wait until a previously hidden tab
was shown; and the Throttle dialog needed a fixed Close footer around scrollable
settings. Session titles also now preserve the path when raw query markers or
spaces are present. Regression tests cover the hidden-to-visible layout lifecycle
and path extraction.

460 regression tests passed: 325 Burp, 91 shared-core, 28 CLI and 16 loopback
smoke tests. The Burp suite was repeated after the final layout corrections.
The final committed artifact is reloaded for the five fresh tabs, imported Sweep
layout and Throttle footer; its hash and results are recorded with the evidence.

These runs verify the listed native paths. They do not exhaust every protocol,
import format, retry combination or external target behavior. Fixture response
signals and direct self-test callbacks are verification evidence, not findings
against a real application. Cleanup removes only the disposable instance and
its private licensed settings; proof artifacts remain.
