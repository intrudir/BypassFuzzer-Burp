#!/usr/bin/env python3
"""Audit Burp/CLI parity. Exit 1 means observed gaps; exit 2 means audit failure.

Run from any directory: python3 scripts/audit-cli-parity.py [--output DIRECTORY]
Builds both artifacts, probes production classes and runs the four packaged CLI
modes against the existing isolated loopback lab. Does not change application code.
The JSON report distinguishes runtime observations, source evidence and limitations.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]


def run(command, output, env=None):
    with output.open("w") as log:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"Command exited {result.returncode}; see {output}")


def duplicates():
    core = {p.name: p for p in (ROOT / "core/src/main/java").rglob("*.java")}
    found = []
    for burp in sorted((ROOT / "src/main/java").rglob("*.java")):
        if burp.name not in core:
            continue
        shared = core[burp.name]
        def normalize(text):
            text = re.sub(r"(?m)^package .*?;|^import .*?;", "", text)
            # Extraction changed visibility but did not centralize these parsers.
            text = re.sub(r"\bpublic\s+", "", text)
            return re.sub(r"\s+", "", text)
        if normalize(burp.read_text()) == normalize(shared.read_text()):
            found.append({"burp": str(burp.relative_to(ROOT)), "core": str(shared.relative_to(ROOT)),
                          "lines": len(shared.read_text().splitlines()),
                          "comparison": "identical after removing package, imports, visibility and whitespace"})
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (args.output or ROOT / "artifacts/verification/surface-parity" / (stamp + f"-{os.getpid()}")).resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    java = shutil.which("java")
    local_java = ROOT / ".gradle/jdks/temurin-17/bin/java"
    if local_java.is_file():
        java = str(local_java)
    if not java:
        raise RuntimeError("Java 17+ is required; run sh build.sh first")
    env["JAVA_HOME"] = str(Path(java).resolve().parents[1])
    env["PATH"] = str(Path(java).parent) + os.pathsep + env.get("PATH", "")

    print("Building artifacts, running fresh tests and preparing audit classpath...", flush=True)
    with tempfile.TemporaryDirectory(prefix="bypassfuzzer-parity-") as temporary:
        init = Path(temporary) / "audit.gradle"
        init.write_text('''gradle.projectsEvaluated {
    rootProject.tasks.register('surfaceParityClasspath') {
        dependsOn rootProject.tasks.named('testClasses'), rootProject.project(':cli').tasks.named('classes')
        doLast {
            println 'PARITY_CLASSPATH=' + rootProject.sourceSets.test.runtimeClasspath.asPath +
                File.pathSeparator + rootProject.project(':cli').sourceSets.main.runtimeClasspath.asPath
        }
    }
}
''')
        run(["sh", "build.sh", "--no-daemon", "--quiet", "--rerun-tasks", "-I", str(init),
             "surfaceParityClasspath", "shadowJar", ":cli:shadowJar", "test", ":core:test", ":cli:test", "smokeTestPlaybooks"],
            output / "build.log", env)
        classpath = next(line.removeprefix("PARITY_CLASSPATH=") for line in
                         (output / "build.log").read_text().splitlines() if line.startswith("PARITY_CLASSPATH="))
        print("Comparing production planners and request policies...", flush=True)
        classes = Path(temporary) / "classes"
        classes.mkdir()
        run([str(Path(java).with_name("javac")), "--class-path", classpath, "-d", str(classes),
             str(ROOT / "scripts/SurfaceParityAudit.java")], output / "compile-probe.log", env)
        run([java, "--class-path", str(classes) + os.pathsep + classpath,
             "com.bypassfuzzer.burp.core.coverage.SurfaceParityAudit",
             str(output / "runtime.json")], output / "runtime.log", env)

    runtime = json.loads((output / "runtime.json").read_text())
    live = []
    helper = ROOT / ".agents/skills/verify-bypassfuzzer-cli/helpers/live_drive.py"
    for mode in ("sweep", "bypass", "idor", "url-validation"):
        print(f"Driving packaged CLI {mode} against loopback...", flush=True)
        directory = output / mode
        directory.mkdir()
        verifier = ROOT / ".agents/skills/verify-bypassfuzzer-cli/helpers/verify.sh"
        health_id = "parity-" + stamp + "-" + mode
        run([str(verifier), "doctor", health_id], directory / "doctor-before-drive.log", env)
        try:
            run([sys.executable, str(helper), str(ROOT / "cli/build/libs/bypassfuzzer-cli.jar"),
                 str(directory), mode], directory / "drive.log", env)
        except RuntimeError:
            run([str(verifier), "doctor", health_id], directory / "doctor-after-failure.log", env)
            raise
        finally:
            run([str(verifier), "cleanup", health_id], directory / "cleanup.log", env)
        live.append({"mode": mode, "status": "PASS", "evidence": str(directory),
                     "assertions": json.loads((directory / "assertions.json").read_text())})

    duplicate_files = duplicates()
    checks = runtime["checks"]
    checks.append({"id": "centralized-source", "status": "FAIL" if duplicate_files else "PASS",
                   "evidence": {"duplicateFiles": duplicate_files}})
    legacy = [str(p.relative_to(ROOT)) for area in ("src/main/java/com/bypassfuzzer/burp/core/attacks", "src/main/java/com/bypassfuzzer/burp/core/idor")
              for p in (ROOT / area).rglob("*.java") if p.name not in
              {"AttackResult.java", "AttackType.java", "IdorEngine.java", "IdorOptions.java", "IdorRunOptions.java"}]
    core_boundary = [str(p.relative_to(ROOT)) for p in (ROOT / "core/src/main/java").rglob("*.java")
                     if "burp.api.montoya" in p.read_text() or "com.bypassfuzzer.burp." in p.read_text()]
    checks.append({"id": "one-production-implementation", "status": "FAIL" if legacy or core_boundary else "PASS",
                   "evidence": {"legacyImplementations": legacy, "coreHostDependencies": core_boundary}})
    report = {
        "schemaVersion": 1,
        "status": "FAIL" if any(check["status"] == "FAIL" for check in checks) else "PASS",
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "artifacts": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in
                      (ROOT / "build/libs/bypassfuzzer.jar", ROOT / "cli/build/libs/bypassfuzzer-cli.jar")},
        "checks": checks,
        "cliOptions": runtime["cliOptions"],
        "idorSharedFamilies": runtime["idorSharedFamilies"],
        "liveCliChecks": live,
        "sharedImplementations": {
            "payloadsAndInput": "core/src/main/java/com/bypassfuzzer/core",
            "headersAndUserAgent": "core/src/main/java/com/bypassfuzzer/core/http/RequestHeaderPolicy.java",
            "sweep": "core/src/main/java/com/bypassfuzzer/core/scan/SweepWorkflow.java",
            "deferredRetries": "core/src/main/java/com/bypassfuzzer/core/scan/DeferredRetryRunner.java",
            "adaptiveThrottle": "core/src/main/java/com/bypassfuzzer/core/throttle/HostThrottleCoordinator.java",
            "globalTraffic": "core/src/main/java/com/bypassfuzzer/core/throttle/GlobalTrafficGovernor.java",
            "resultFilters": "core/src/main/java/com/bypassfuzzer/core/filter",
            "retryInterchange": "core/src/main/java/com/bypassfuzzer/core/input/RetryPackage.java",
        },
        "limits": [
            "The audit compares actual CLI previews against the Burp adapters and exercises loopback traffic; it cannot prove behavior on arbitrary targets.",
            "Burp boundary probes use the repository's duplicate-preserving Montoya test request adapter; the real Burp GUI was not driven.",
            "The four CLI smoke drives prove live request/evidence behavior, not equivalence to the Burp UI.",
            "Dashboard, context menus, Burp proxy history and editor rendering are host-specific UI features; scan semantics still require parity.",
        ],
    }
    suites = []
    for project in (ROOT, ROOT / "core", ROOT / "cli"):
        for task in (("test", "smokeTestPlaybooks") if project == ROOT else ("test",)):
            for file in sorted((project / "build/test-results" / task).glob("TEST-*.xml")):
                suite = ET.parse(file).getroot()
                suites.append({"task": task, **{key: suite.attrib.get(key, "0") for key in ("name", "tests", "failures", "errors", "skipped")}})
    report["existingTestResults"] = suites
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    for check in checks:
        print(f"{check['status']}: {check['id']}")
    print(f"Report: {output / 'report.json'}")
    return 1 if report["status"] == "FAIL" else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, StopIteration, ValueError) as error:
        print(f"Audit could not finish: {error}", file=sys.stderr)
        sys.exit(2)
