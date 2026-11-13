# Transport, evidence and Sweep recovery boundaries

## Sub-features

- TLS verifies the chain and socket-origin hostname; a fuzzed Host value never changes peer identity. Explicit `--insecure` remains available.
- HTTP/0.9 retains nonempty body-only replies, rejects an empty disconnect, and enforces the same 64 MiB response-body limit as other transports.
- Results exports reject the input file and its hard-link, symbolic-link and normalized-path aliases before opening the output; ordinary exports preserve the source.
- Authenticated Sweep keeps anonymous verification in its current protocol pass. BOTH has separate HTTP/1 and HTTP/2 verification and public-endpoint decisions.
- Successful automatic retries recompute signals, finding counts and fallback annotations using retained comparison context.

## How to get to it (user POV)

Use Bypass/Sweep with `--protocol`, `--insecure`, retry and calibration controls. Use `results --input <evidence> --output <different-file>` after the scan. Burp's corresponding import and retry actions are in the native Sweep map.

## Driving it with the CLI helper

Use a fresh run ID, then `verify.sh doctor <run-id>` and `verify.sh drive <run-id> boundaries`.
This drive additionally requires `openssl`, JDK `keytool`, and Python's `h2` package.
The helper invokes only the packaged JAR and starts owned loopback HTTP/1 and HTTP/2 servers. It creates a temporary localhost-only certificate and isolated child-JVM trust store, tests matching/wrong/untrusted identities plus explicit insecure mode, and reads every referenced raw exchange. It tests a host whose anonymous HTTP/1 endpoint is blocked while HTTP/2 is public: HTTP/1 must run and flag recovered mutations; HTTP/2 may skip its genuinely public endpoint; BOTH must preserve both contexts. Blocked Sweep retries must also refresh their signals and finding counts.

The fixture's headerless servers close without bytes, send a small valid body, or stream 65 MiB. Empty/oversized replies must yield retained transport errors with no fabricated successful response. The transport regression also accepts the exact 64 MiB boundary. Export cases require exit 2 and byte-identical input for every supported alias, then prove a separate export succeeds. Alias types unavailable on the host are recorded explicitly.

Retain commands, stdout/stderr, the complete per-case scan trees, observed wire requests, assertions and cleanup. The helper deletes temporary TLS keys/trust stores and stops its fixture even after a failed assertion. `NettyRequestTransportSafetyTest`, `SweepRecoveryTest`, `CliSweepRecoveryTest` and `CliParityTest` provide the matching regression coverage.

## Gotchas

- Use a fresh run ID; never overwrite evidence from a failed attempt.
- The TLS certificates and credentials are generated or synthetic fixtures, never operator credentials.
- HTTP/0.9 has no status line: its nonempty body-only response uses a synthetic 200. Empty EOF is unavailable; inspect raw protocol evidence before calling a bypass.
- The equivalent Burp OpenAPI redirect policy requires a real native import check. The CLI remote-spec loader does not forward scan credential headers.
