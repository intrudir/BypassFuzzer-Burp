---
name: verify-bypassfuzzer-cli
description: Verify BypassFuzzer's standalone CLI commands, local HTTP behavior, and evidence output after CLI or shared-core changes.
---

# Verify BypassFuzzer CLI

Use this skill after changing the CLI, shared planners, HTTP transport, input parsing, evidence output, or CLI packaging. Read `features/README.md`, then the feature file being verified.

## Launch

From the repository root, build the exact executable JAR that users run:

```bash
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
./.agents/skills/verify-bypassfuzzer-cli/helpers/verify.sh launch "$RUN_ID"
```

Readiness requires `cli/build/libs/bypassfuzzer-cli.jar`, a `Main-Class` of `com.bypassfuzzer.cli.BypassFuzzerCli`, the Gradle project version in its manifest, and working root/subcommand help. The helper records the JAR hash and build transcript under `artifacts/verification/bypassfuzzer-cli/<RUN_ID>/`.

## Doctor

Run the read-only artifact doctor before each drive:

```bash
./.agents/skills/verify-bypassfuzzer-cli/helpers/verify.sh doctor "$RUN_ID"
```

It checks Java and Python, manifest metadata, packaged payload resources, the four command names, and each subcommand's `--help`. Do not drive an older JAR after source or build configuration changes; launch again first.

## Drive

Drive one real CLI mode against the helper's isolated loopback lab:

```bash
./.agents/skills/verify-bypassfuzzer-cli/helpers/verify.sh drive "$RUN_ID" bypass
```

Feature IDs are `sweep`, `bypass`, `idor`, and `url-validation`. Each drive invokes the packaged JAR as a subprocess with ordinary CLI flags, captures stdout/stderr/exit status, reads `summary.json` and `results.jsonl`, follows every request/response reference, and verifies that stored authorization is redacted. It also proves a YAML key containing `collaborator` is rejected with exit code 2 before a scan starts. The lab binds an ephemeral loopback port and is stopped by the driver that created it.

The Bypass drive additionally requires a blocked baseline, an emitted trusted-proxy IP header mutation, a `200` lab response marker, and a `LIKELY_BYPASS` result. IDOR requires its two control baselines first. URL Validation requires marker substitution. Sweep requires a high-signal run scoped by its URL-list input.

## Evidence

Evidence survives under `artifacts/verification/bypassfuzzer-cli/<RUN_ID>/`. Each feature retains `command.json`, `stdout.jsonl`, `stderr.log`, `lab-requests.json`, `assertions.json`, the CLI's complete `scan/` evidence tree, and `collaborator-boundary.log`.

A passing proof must use the packaged CLI, observe loopback HTTP traffic, read the referenced raw evidence, and confirm output permissions and redaction. Internal planner calls alone are not CLI proof. Native HTTP/2 framing remains covered by `NettyRequestTransportTest`; run the full Gradle test suite when transport changes.

## Cleanup

Run cleanup after every pass or failure:

```bash
./.agents/skills/verify-bypassfuzzer-cli/helpers/verify.sh cleanup "$RUN_ID"
```

The live driver owns and closes its in-process loopback server. Cleanup removes only a run-local scratch directory and any exact PID recorded there; it never kills by name and never deletes evidence.

## Helpers

`helpers/verify.sh` is the executable entry point:

```text
verify.sh launch  <run-id>
verify.sh doctor  <run-id>
verify.sh drive   <run-id> <sweep|bypass|idor|url-validation>
verify.sh cleanup <run-id>
```

`helpers/live_drive.py` implements the isolated lab and black-box assertions; invoke it through `verify.sh` so paths and evidence are consistent.
