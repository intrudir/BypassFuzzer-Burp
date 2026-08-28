---
name: verify-bypassfuzzer
description: Verify BypassFuzzer's Burp Suite desktop tabs, request-routing menus, and live authorization-bypass behavior after changes to the extension.
---

# Verify BypassFuzzer

Use this skill after changing BypassFuzzer's Swing UI, Montoya integration, request mutation, result handling, or bundled payloads. The primary user surface is the `BypassFuzzer` tab inside Burp Suite. The repository also provides a Gradle-controlled Swing harness and an isolated vulnerable HTTP lab; those are the repeatable automation surface.

Read `features/README.md`, then open the feature file for the behavior being changed. Do not substitute a convenient feature for a mapped entry point.

## Launch

BypassFuzzer has no standalone process: Burp constructs `com.bypassfuzzer.burp.BurpExtender` and owns its lifecycle. For automated verification, launch means producing the exact JAR that Burp loads:

```bash
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
./.agents/skills/verify-bypassfuzzer/helpers/verify.sh launch "$RUN_ID"
```

The command runs `sh build.sh --no-daemon shadowJar` and requires `build/libs/bypassfuzzer.jar`. Readiness is the successful build plus a manifest whose `Implementation-Title` is `BypassFuzzer` and whose `Implementation-Version` matches `build.gradle`.

For a human-visible Burp check, use a disposable Burp project, go to `Extensions` -> `Installed` -> `Add`, choose extension type `Java`, and select the absolute path to `build/libs/bypassfuzzer.jar`. It is ready when the extension output contains `BypassFuzzer extension loaded successfully!` and the suite shows the `BypassFuzzer` tab with `Dashboard`, `Sweep`, `Bypass`, `IDOR`, and `URL Validation`.

Do not automate or reconfigure a Burp process that this verification run did not start. In particular, do not load or unload the JAR in an already-running interactive Burp session. Burp's project, license, extension, and proxy state are shared user state; the repository does not provide a supported isolated GUI launcher. Use the repository harness for unattended verification and reserve the live Burp check for an explicitly disposable project.

## Doctor

Run the artifact doctor before every drive and whenever the build or Burp load looks wrong:

```bash
./.agents/skills/verify-bypassfuzzer/helpers/verify.sh doctor "$RUN_ID"
```

This is read-only with respect to the extension and targets. It checks Java 17+, the installed Burp launcher, the JAR manifest, the Montoya entry point, the bundled Sweep and URL Validation resources, and the exact JAR SHA-256. A live Burp instance is worth driving only if its extension output has both the loading and loaded-successfully messages, the five top-level tabs are visible, and it is a disposable project owned by the run.

## Drive

Use the helper from the repository root:

```bash
./.agents/skills/verify-bypassfuzzer/helpers/verify.sh drive "$RUN_ID" bypass
```

Supported feature IDs are `dashboard`, `sweep`, `bypass`, `idor`, and `url-validation`. Each command drives named Swing controls or table actions from production UI classes through the existing JUnit harness. `bypass` and `url-validation` additionally start a test-local vulnerable lab, send real HTTP traffic through production attack engines, assert the response-side bypass marker, and tear the lab down.

The Sweep drive also proves complete `All payloads` execution, exact concurrency limits, lazy candidate planning, bounded batched Swing delivery, and temp-file-backed raw evidence. Those delivery and evidence checks cover the shared results workspace used by every attack mode.

The Dashboard drive also injects a synthetic newer-version result into the production suite banner, verifies its current/latest-version message, and dismisses it. It does not depend on the external update manifest.

For the mapped Bypass path, the harness proves all three layers of the user journey:

- `Send to BypassFuzzer` -> `Bypass` dispatches the selected request into a nested `Bypass` session.
- The session exposes `Start Fuzzing`, `Stop`, `Pause`, `Clear Results`, `Options...`, attack-family checkboxes, and the results workspace.
- Every throttle response and automatic retry attempt remains visible; exhausted or capacity-rejected payloads remain in the shared retry queue, and planned/send/result counts are distinct.
- The production Header attack sends mutated requests to `/edge/private/reports/quarterly` and finds the lab's `trusted X-Forwarded-For` bypass response.

The harness is not proof that Burp rendered correctly on a particular workstation. When the change affects visual layout, dialog sizing, editor rendering, keyboard focus, or Burp theme integration, repeat the feature's user-POV path in a disposable Burp project and add screenshots plus the extension output transcript to the same evidence directory.

## Evidence

Evidence survives at `artifacts/verification/bypassfuzzer/<RUN_ID>/`. The helper records:

- `launch.log`, manifest metadata, Git revision, and the JAR hash;
- `doctor.txt` with every checked class and resource;
- one command transcript per driven layer;
- copied Gradle XML results, including exact test names and zero/nonzero failure counts;
- for live attack features, the local-lab request outcome and response-marker assertions.

A valid proof exercises the actual menu/control path and the resulting engine behavior. Capture the action and resulting state, not only the final table. For network mutations, require both the emitted attack test and an observed HTTP status/body/header assertion. Do not use internal setters as proof. Mocks are acceptable only at the Montoya/Burp boundary already isolated by the production `RequestSender` interface; attack generation, engine sequencing, and the local HTTP round trip remain real.

For a manual GUI pass, store `before.png`, `after.png`, and `extension-output.txt` under `artifacts/verification/bypassfuzzer/<RUN_ID>/manual/<feature-id>/`. Screenshots must include the `BypassFuzzer` tab identity. If a feature writes a file, also retain the file or a hash and read it back through the relevant user surface.

## Cleanup

Run cleanup even after a failed or interrupted drive:

```bash
./.agents/skills/verify-bypassfuzzer/helpers/verify.sh cleanup "$RUN_ID"
```

The helper starts Gradle and every test-local lab in a dedicated process group. Its signal trap terminates only that process group; it never kills by process name. Normal JUnit cleanup stops the lab first. The explicit cleanup removes only run scratch state and confirms the evidence directory remains. It does not unload the extension from Burp, close a user project, remove the built JAR, or delete proof artifacts.

For a manual disposable Burp check, unload the extension and close only the disposable project created for this run. Never use cleanup to alter an existing Burp session.

## Helpers

`helpers/verify.sh` is executable and is the only helper. Its contract is:

```text
verify.sh launch  <run-id>
verify.sh doctor  <run-id>
verify.sh drive   <run-id> <dashboard|sweep|bypass|idor|url-validation>
verify.sh cleanup <run-id>
```

Run it from the repository root. Run IDs may contain letters, numbers, dots, underscores, and hyphens. The helper prints the absolute evidence directory on success.
