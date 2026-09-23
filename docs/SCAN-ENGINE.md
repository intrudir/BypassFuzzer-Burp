# Shared scan engine

`core` owns the transport-neutral request model, payload generation, IDOR slot discovery, request admission, pacing, retries, and the default response signals. The CLI and Burp extension convert inputs into `HttpRequestData`, execute core plans, and render the resulting events through their own evidence or UI adapters.

| Mode | Shared plan | Execution |
| --- | --- | --- |
| Bypass | `BypassPlanner` | `ScanEngine.run` in both surfaces |
| IDOR | `IdorPlanner` | `ScanEngine.run` in both surfaces |
| URL Validation | `UrlValidationPlanner` and core payload generator | `ScanEngine.run` in both surfaces |
| Sweep | `HighSignalPlanner` or `BypassPlanner` | `ScanEngine.run` in CLI; `ScanEngine.exchange` supplies admission and pacing to Burp's Proxy-history candidate, canary retry, and evidence workflow |

Burp-specific classes in `src/main/java/com/bypassfuzzer/burp/http` translate Montoya requests and responses at the boundary. Burp's URL Validation payload generator and Sweep probe generator are adapters over the core catalogs. Burp owns Proxy history discovery, Collaborator payload creation, session controls, and result presentation. CLI owns file/API imports, Netty transport, YAML parsing, and on-disk evidence.

IDOR requires an exact selected identifier slot. It sends the authorized control and target baseline serially, then sends standard IDOR mutations when the authorized control succeeds and the target baseline returns 2xx, 401, 403, or 404. A 2xx target baseline is marked for review rather than treated as proof of direct access: a successful status can still contain diminished permissions. A redirect or failed control stops standard mutations as inconclusive. For a 2xx target baseline, any changed mutation body is flagged for review against that baseline. IDOR defaults to serial execution, every applicable mutation from enabled playbooks without a numeric cap, and no automatic retry of state-changing methods. The optional unique JSON pointer gives each planned create request a distinct value. Both interfaces can preview the plan before sending.

The response-guided mass-assignment family is enabled by default. After baselines, the shared planner discovers exact identifier values in JSON response fields and adds authorized-path/body and target-path/body probes. Authorized-path probes require only a successful authorized control; target-path probes require a comparable target baseline (2xx, 401, 403, or 404). The family uses `/name` as a unique create field when available unless another unique JSON pointer is configured. Captured responses seed offline previews, while live baselines determine execution probes.

The shared paired-control separator family is also enabled by default. Its inventory combines only the two supplied IDs, with ten priority probes for both directions of LF, CRLF, CR, NUL, and tab before normal round-robin scheduling. Core discovers exact text, XML, multipart text-field, selected header, and cookie locations in addition to path, query, form, and JSON. It encodes separators according to the selected context, omits unsupported characters rather than sending malformed request framing, and reports eligible versus capped probe counts in both previews.

The shared IDOR planner excludes DANGEROUS families that guess other standalone identifiers from its default set: numeric pivots, special identifier values (`0`, `1`, `-1`), JSON numeric edge cases, canonical ID formats, and truncated ID variants. These can address objects beyond the two chosen IDs. Burp marks each in the selector and requires confirmation on an off-to-on change. CLI users must include each family ID explicitly and receive a stderr warning. Bypass planning is unchanged.

When adding a payload family, change its core planner or payload resource, then test the plan in `core` and verify both packaged surfaces. Keep transport and UI types out of `core`.
