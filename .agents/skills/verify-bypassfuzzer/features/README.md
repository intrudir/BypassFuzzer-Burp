# BypassFuzzer verification map

This directory is the maintained map of BypassFuzzer's user-facing Burp Suite extension behavior. Read this index first, then drive the matching feature file. The primary surface is Swing UI embedded in Burp; Gradle-controlled Swing tests and test-local HTTP labs provide the unattended control mechanism.

## Baseline preconditions

- Run from the repository root with Java 17+, Python 3, `/usr/bin/burpsuite`, `setsid`, and `unzip` available.
- Create a unique `RUN_ID`, then run `helpers/verify.sh launch <RUN_ID>` and `helpers/verify.sh doctor <RUN_ID>`.
- Require `build/libs/bypassfuzzer.jar` with manifest title `BypassFuzzer` and the version declared in `build.gradle`.
- Treat any already-running Burp process as user-owned. Do not click it, change its extensions, proxy settings, project, or user configuration.
- Use a disposable Burp project for visual checks. The unattended harness uses headless Swing controls and a test-local vulnerable lab instead of a shared Burp instance.
- Send real HTTP mutations only to the repository's loopback vulnerable lab unless the user explicitly authorizes another target.

## Driving conventions

- Start every recipe with the artifact doctor and the feature's listed preconditions.
- In Burp, use visible tab names, menu text, button labels, field labels, and table actions exactly as written.
- In automation, run `./.agents/skills/verify-bypassfuzzer/helpers/verify.sh drive <RUN_ID> <feature-id>`.
- A Swing test proves a named UI action/state; an engine test proves request generation or session behavior; a live smoke test proves the HTTP side effect. Do not claim one layer proves another.
- `Send to BypassFuzzer` is available from a selected request in Burp's Proxy, Sitemap, or Repeater message editor and has `Bypass`, `IDOR`, and `URL Validation` children.
- Close or unload only sessions created in a disposable project. Do not remove evidence during cleanup.

## Proof and skip reporting

- Capture the user action and resulting tab, status, table, dialog, or file—not only the final screen.
- Automated proof requires the feature's command transcript plus copied zero-failure Gradle XML.
- Network proof requires a baseline and a mutated response assertion. The local lab exposes `X-Smoke-Bypass` markers for the vulnerable behavior.
- A manual visual proof requires `before.png`, `after.png`, and `extension-output.txt` with the `BypassFuzzer` identity visible.
- Record the feature ID and exact entry point with every manual artifact.
- Report a Burp-only path as unverified when no disposable Burp project is available. Do not substitute a mocked or different entry point.
- Do not describe a skipped mode, import source, menu child, or results action as covered by another path.

## Feature entry contract

Each feature file describes the visible behavior, all major user entry points, exact control labels, observable proof, and feature-specific traps. The four H2 sections stay in the prescribed order so future maintenance can compare this map to the source.

## Features

- [Dashboard and global control](./dashboard.md) covers activity visibility, per-row actions, global pause/stop, extension-wide traffic limits, and update notices.
- [Coverage Sweep](./sweep.md) covers Proxy-history modes, imports, candidate/probe preview, execution controls, results, retry queue, and export.
- [Targeted authorization bypass](./bypass.md) covers context-menu routing, attack selection/options, execution, filtering, result inspection, and retry.
- [IDOR / BOLA analysis](./idor.md) covers identifier setup, baselines, playbooks, run options, diagnostics, results, and retry.
- [URL Validation](./url-validation.md) covers marker-driven request editing, payload contexts/settings, preview, execution, and results.
