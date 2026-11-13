# AuthZ Bypass Playbooks

Bypass mutates a captured request and compares responses with its original
control. Status changes, different content and possible fallback matches are
leads to inspect against the intended protected resource.

## Workflow

1. Right-click a request in Burp and choose Send to BypassFuzzer → Bypass.
2. Select attack families or use Playbooks… for exact catalog entries, additional
   API prefixes and wildcard calibration.
3. Preview Requests, then Start Fuzzing. Hide config gives results and the
   request/response viewers more space.
4. Inspect candidate exchanges and any Fallback control. Use Edit run… to pause,
   drain requests, change scope/limits/playbooks/headers and resume.

Family shortcuts cover Header, Path, Verb, Debug Params, Debug Cookies,
Trailing Dot, Trailing Slash, Extension, Content-Type, Encoding, Protocol and
Case Variation. The shared catalog defines the selectable IDs for both Burp
and the CLI; individual payload patterns within a family are not separate IDs.

## Catalog and execution

[Shared bypass playbooks and calibration](https://github.com/intrudir/BypassFuzzer-Burp/blob/main/docs/bypass-playbooks.md)
describes exact selection, protocol requirements, method gating and fallback
annotations. Obtain the current executable inventory without target traffic:

```sh
java -jar cli/build/libs/bypassfuzzer-cli.jar bypass --list-playbooks
```

Generation lives in `core.scan.BypassPlaybooks` and `core.scan.BypassPlanner`.
The shared `ScanEngine` executes plans; Burp supplies Montoya transport,
Collaborator integration and result presentation. Contributor boundaries are
in [the engine guide](https://github.com/intrudir/BypassFuzzer-Burp/blob/main/docs/SCAN-ENGINE.md).

The socket origin stays fixed during mutation. A changed path, status or body
does not establish access to the intended resource: confirm the returned data
and compare against wildcard/fallback behavior before treating it as a bypass.
