#!/usr/bin/env python3
"""Locate BypassFuzzer CLI, run it unchanged, and triage schema-v1 evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


MINIMUM_VERSION = (1, 4, 4)
SCAN_COMMANDS = ("sweep", "bypass", "idor", "url-validation")
COMMANDS = (*SCAN_COMMANDS, "results")
REQUIRED_OPTIONS = {
    "sweep": ("--preview", "--sweep-mode", "--openapi-variable", "--openapi-parameter-policy", "--oob-generator", "--control-file", "--playbooks", "--list-playbooks", "--api-prefix", "--wildcard-calibration"),
    "bypass": ("--preview", "--oob-generator", "--control-file", "--playbooks", "--list-playbooks", "--api-prefix", "--wildcard-calibration"),
    "idor": ("--id-location", "--baseline-response", "--unique-json-field"),
    "url-validation": ("--oob-generator", "--contexts"),
    "results": ("--response-regex", "--smart-repeats", "--format", "--show-calibration"),
}
DEFAULT_SIGNALS = (
    "LIKELY_BYPASS",
    "IDOR_CANDIDATE",
    "MASS_ASSIGNMENT_CANDIDATE",
    "RESPONSE_CHANGED",
    "THROTTLED",
    "NO_RESPONSE",
)


class BypassFuzzerError(RuntimeError):
    """Expected resolution, compatibility, or evidence-integrity failure."""


def _is_executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def _invocation_for_path(path: Path, environ: Mapping[str, str]) -> list[str]:
    resolved = path.expanduser().resolve()
    if resolved.suffix.lower() == ".jar":
        if not resolved.is_file():
            raise BypassFuzzerError(f"BypassFuzzer JAR does not exist: {resolved}")
        java = shutil.which("java", path=environ.get("PATH"))
        if java is None:
            raise BypassFuzzerError("Java is required to run the BypassFuzzer CLI JAR")
        return [java, "-jar", str(resolved)]
    if not _is_executable(resolved):
        raise BypassFuzzerError(f"BypassFuzzer CLI is not executable: {resolved}")
    return [str(resolved)]


def resolve_cli(
    cwd: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> list[str]:
    """Resolve a BypassFuzzer invocation using stable, documented precedence."""
    environment = os.environ if environ is None else environ
    override = environment.get("BYPASSFUZZER_CLI", "").strip()
    if override:
        return _invocation_for_path(Path(override), environment)

    installed = shutil.which("bypassfuzzer", path=environment.get("PATH"))
    if installed:
        return [str(Path(installed).resolve())]

    start = (cwd or Path.cwd()).resolve()
    # A repository-owned skill must also work from a separate engagement workspace.
    skill = Path(__file__).resolve().parent
    directories = dict.fromkeys((start, *start.parents, skill, *skill.parents))
    for directory in directories:
        for relative in (
            Path("cli/build/libs/bypassfuzzer-cli.jar"),
            Path("build/libs/bypassfuzzer-cli.jar"),
            Path("bypassfuzzer-cli.jar"),
        ):
            candidate = directory / relative
            if candidate.is_file():
                return _invocation_for_path(candidate, environment)

    raise BypassFuzzerError(
        "BypassFuzzer CLI was not found. Set BYPASSFUZZER_CLI to an executable "
        "or JAR, install bypassfuzzer on PATH, or build cli/build/libs/"
        "bypassfuzzer-cli.jar in a source checkout."
    )


def _run_capture(invocation: Sequence[str], arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*invocation, *arguments],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _numeric_version(text: str) -> tuple[tuple[int, int, int], str]:
    match = re.search(r"BypassFuzzer\s+CLI\s+(\d+)\.(\d+)\.(\d+)(?:[-+][^\s]+)?", text)
    if not match:
        raise BypassFuzzerError(
            "Unable to read a numeric BypassFuzzer CLI version; version 1.4.4 or newer is required"
        )
    value = tuple(int(part) for part in match.groups())
    return value, match.group(0).split()[-1]


def validate_cli(invocation: Sequence[str]) -> dict[str, Any]:
    version_result = _run_capture(invocation, ["--version"])
    if version_result.returncode != 0:
        raise BypassFuzzerError(
            f"BypassFuzzer --version failed with exit {version_result.returncode}: "
            f"{(version_result.stderr or version_result.stdout).strip()}"
        )
    parsed, display = _numeric_version(version_result.stdout + "\n" + version_result.stderr)
    if parsed < MINIMUM_VERSION:
        minimum = ".".join(str(part) for part in MINIMUM_VERSION)
        raise BypassFuzzerError(f"BypassFuzzer CLI {display} is too old; {minimum} or newer is required")

    root_help = _run_capture(invocation, ["--help"])
    if root_help.returncode != 0:
        raise BypassFuzzerError(f"BypassFuzzer --help failed with exit {root_help.returncode}")
    root_text = root_help.stdout + "\n" + root_help.stderr
    missing = [command for command in COMMANDS if command not in root_text]
    if missing:
        raise BypassFuzzerError("BypassFuzzer root help lacks commands: " + ", ".join(missing))

    for command in COMMANDS:
        result = _run_capture(invocation, [command, "--help"])
        text = result.stdout + "\n" + result.stderr
        if result.returncode != 0 or f"bypassfuzzer {command}" not in text.lower():
            raise BypassFuzzerError(f"BypassFuzzer command is unavailable or incompatible: {command}")
        missing_options = [option for option in REQUIRED_OPTIONS[command] if option not in text.replace("--[no-]", "--")]
        if missing_options:
            raise BypassFuzzerError(f"BypassFuzzer {command} lacks options: " + ", ".join(missing_options))
        if command != "results" and ("JSON atomic edits" not in " ".join(text.split()) or ".status.json" not in text):
            raise BypassFuzzerError(f"BypassFuzzer {command} lacks the pause/edit/resume status contract")

    source = invocation[-1] if "-jar" in invocation else invocation[0]
    return {
        "state": "PASS",
        "version": display,
        "minimumVersion": ".".join(str(part) for part in MINIMUM_VERSION),
        "source": source,
        "commands": list(COMMANDS),
    }


def run_cli(invocation: Sequence[str], arguments: Sequence[str]) -> int:
    if not arguments or arguments[0] not in COMMANDS:
        raise BypassFuzzerError("run requires one of: " + ", ".join(COMMANDS))
    validate_cli(invocation)
    return subprocess.run([*invocation, *arguments], check=False).returncode


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BypassFuzzerError(f"Missing {label}: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise BypassFuzzerError(f"Unable to read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise BypassFuzzerError(f"{label} must contain a JSON object: {path}")
    return value


def _read_records(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise BypassFuzzerError(f"Missing results JSONL: {path}") from exc
    except OSError as exc:
        raise BypassFuzzerError(f"Unable to read results JSONL {path}: {exc}") from exc

    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise BypassFuzzerError(f"Invalid JSONL record at line {line_number}: {exc}") from exc
        if not isinstance(value, dict):
            raise BypassFuzzerError(f"JSONL line {line_number} is not an object")
        records.append(value)
    return records


def _safe_reference(root: Path, reference: Any, label: str, optional: bool = False) -> Path | None:
    if reference is None and optional:
        return None
    if not isinstance(reference, str) or not reference:
        raise BypassFuzzerError(f"{label} is missing or is not a string")
    relative = Path(reference)
    if relative.is_absolute():
        raise BypassFuzzerError(f"{label} must be relative: {reference}")
    resolved = (root / relative).resolve()
    if resolved != root and root not in resolved.parents:
        raise BypassFuzzerError(f"{label} escapes the evidence directory: {reference}")
    if not resolved.is_file():
        raise BypassFuzzerError(f"{label} does not exist: {reference}")
    return resolved


def _body_digest(path: Path | None) -> str | None:
    if path is None:
        return None
    raw = path.read_bytes()
    marker = raw.find(b"\r\n\r\n")
    width = 4
    if marker < 0:
        marker = raw.find(b"\n\n")
        width = 2
    body = raw if marker < 0 else raw[marker + width :]
    return hashlib.sha256(body).hexdigest()


def _record_view(record: Mapping[str, Any], request_path: Path, response_path: Path | None) -> dict[str, Any]:
    return {
        "sequence": record.get("sequence"),
        "configurationRevision": record.get("configurationRevision", 0),
        "headerRevision": record.get("headerRevision", record.get("configurationRevision", 0)),
        "target": record.get("target"),
        "protocol": record.get("protocol"),
        "family": record.get("family"),
        "payload": record.get("payload"),
        "encoding": record.get("encoding"),
        "signal": record.get("signal"),
        "retryAttempt": record.get("retryAttempt"),
        "playbookId": record.get("playbookId"),
        "controlRole": record.get("controlRole"),
        "calibration": dict(record.get("calibration") or {}),
        "status": record.get("status"),
        "length": record.get("length"),
        "durationMillis": record.get("durationMillis"),
        "error": record.get("error"),
        "requestPath": str(request_path),
        "responsePath": None if response_path is None else str(response_path),
        "bodySha256": _body_digest(response_path),
    }


def _same(left: Any, right: Any) -> bool | None:
    if left is None or right is None:
        return None
    return left == right


def _baseline_comparisons(candidate: Mapping[str, Any], baselines: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    comparisons = []
    for baseline in baselines:
        comparisons.append(
            {
                "sequence": baseline.get("sequence"),
                "payload": baseline.get("payload"),
                "statusEqual": _same(candidate.get("status"), baseline.get("status")),
                "lengthEqual": _same(candidate.get("length"), baseline.get("length")),
                "bodyEqual": _same(candidate.get("bodySha256"), baseline.get("bodySha256")),
            }
        )
    return comparisons


def build_triage_report(
    output_directory: Path,
    signals: Iterable[str] | None = None,
    include_all: bool = False,
    limit: int = 50,
) -> dict[str, Any]:
    root = output_directory.expanduser().resolve()
    if not root.is_dir():
        raise BypassFuzzerError(f"Evidence directory does not exist: {root}")
    run = _read_json(root / "run.json", "run metadata")
    summary = _read_json(root / "summary.json", "summary")
    records = _read_records(root / "results.jsonl")

    for name, value in (("run.json", run), ("summary.json", summary)):
        if value.get("schemaVersion") != 1:
            raise BypassFuzzerError(f"Unsupported {name} schemaVersion: {value.get('schemaVersion')}")

    expected_records = summary.get("records")
    if not isinstance(expected_records, int) or expected_records != len(records):
        raise BypassFuzzerError(
            f"summary record count {expected_records!r} does not match results count {len(records)}"
        )

    run_id = run.get("runId")
    if not isinstance(run_id, str) or not run_id:
        raise BypassFuzzerError("run.json lacks a runId")

    seen_sequences: set[int] = set()
    views: list[dict[str, Any]] = []
    for index, record in enumerate(records, 1):
        if record.get("schemaVersion") != 1:
            raise BypassFuzzerError(f"Record {index} has unsupported schemaVersion: {record.get('schemaVersion')}")
        if record.get("runId") != run_id:
            raise BypassFuzzerError(f"Record {index} runId does not match run.json")
        sequence = record.get("sequence")
        if not isinstance(sequence, int) or sequence <= 0 or sequence in seen_sequences:
            raise BypassFuzzerError(f"Record {index} has an invalid or duplicate sequence: {sequence!r}")
        seen_sequences.add(sequence)
        request_path = _safe_reference(root, record.get("requestRef"), f"record {sequence} requestRef")
        response_path = _safe_reference(
            root,
            record.get("responseRef"),
            f"record {sequence} responseRef",
            optional=True,
        )
        calibration = record.get("calibration")
        if calibration is not None and not isinstance(calibration, dict):
            raise BypassFuzzerError(f"Record {sequence} calibration must be an object")
        view = _record_view(record, request_path, response_path)
        for key in ("controlRequestRef", "controlResponseRef"):
            if key in view["calibration"]:
                path = _safe_reference(root, view["calibration"][key], f"record {sequence} {key}", optional=True)
                view["calibration"][key.replace("Ref", "Path")] = None if path is None else str(path)
        views.append(view)

    views.sort(key=lambda value: value["sequence"])
    baseline_groups: dict[tuple[Any, Any, Any], list[dict[str, Any]]] = {}
    baselines: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []
    for record, view in zip(sorted(records, key=lambda value: value["sequence"]), views):
        if record.get("controlRole") == "WILDCARD":
            controls.append(view)
        elif record.get("baseline") is True:
            baselines.append(view)
            baseline_groups.setdefault((view["target"], view["protocol"], view["headerRevision"]), []).append(view)

    default_filter = signals is None
    selected_signals = {value.strip().upper() for value in (DEFAULT_SIGNALS if signals is None else signals) if value.strip()}
    candidates = []
    for record, view in zip(sorted(records, key=lambda value: value["sequence"]), views):
        if record.get("baseline") is True:
            continue
        signal = str(view.get("signal", "")).strip().upper()
        sweep_signal = default_filter and record.get("mode") == "sweep" and signal not in ("", "NO_SIGNAL", "BASELINE")
        if not include_all and signal not in selected_signals and not sweep_signal:
            continue
        matching = baseline_groups.get((view["target"], view["protocol"], view["headerRevision"]), [])
        candidate = dict(view)
        candidate["baselineComparisons"] = _baseline_comparisons(candidate, matching)
        candidates.append(candidate)

    total_candidates = len(candidates)
    displayed = candidates if limit == 0 else candidates[:limit]
    return {
        "state": "PASS",
        "root": str(root),
        "runId": run_id,
        "summary": summary,
        "baselines": baselines,
        "controls": controls,
        "candidateCount": total_candidates,
        "displayedCandidateCount": len(displayed),
        "truncated": len(displayed) < total_candidates,
        "candidates": displayed,
    }


def _short(value: Any, maximum: int = 180) -> str:
    text = "" if value is None else str(value).replace("\n", " ")
    return text if len(text) <= maximum else text[: maximum - 1] + "…"


def render_triage_text(report: Mapping[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        f"Evidence: {report['root']}",
        "Summary: "
        f"state={summary.get('state')} mode={summary.get('mode')} "
        f"records={summary.get('records')} findings={summary.get('findings')} "
        f"throttled={summary.get('throttled')} transportErrors={summary.get('transportErrors')}",
        f"Baselines ({len(report['baselines'])}):",
    ]
    for baseline in report["baselines"]:
        lines.append(
            f"  #{baseline['sequence']} [{baseline['protocol']}] "
            f"{_short(baseline['payload'])} status={baseline['status']} length={baseline['length']}"
        )
        lines.append(f"    request={baseline['requestPath']}")
        lines.append(f"    response={baseline['responsePath']}")

    lines.append(f"Fallback controls ({len(report.get('controls', []))}):")
    for control in report.get("controls", []):
        lines.append(f"  #{control['sequence']} [{control['protocol']}] status={control['status']} request={control['requestPath']} response={control['responsePath']}")
    lines.append(
        f"Candidates ({report['displayedCandidateCount']} of {report['candidateCount']}):"
    )
    for candidate in report["candidates"]:
        lines.append(
            f"  #{candidate['sequence']} {candidate['signal']} [{candidate['protocol']}] "
            f"{_short(candidate['family'])}: {_short(candidate['payload'])} "
            f"status={candidate['status']} length={candidate['length']}"
        )
        lines.append(f"    request={candidate['requestPath']}")
        lines.append(f"    response={candidate['responsePath']}")
        calibration = candidate.get("calibration", {})
        if calibration:
            lines.append(f"    calibration={calibration.get('assessment')} {_short(calibration.get('annotation'))}")
            lines.append(f"    fallback request={calibration.get('controlRequestPath')} response={calibration.get('controlResponsePath')}")
        lines.append(f"    configurationRevision={candidate.get('configurationRevision', 0)} headerRevision={candidate.get('headerRevision', 0)}")
        for comparison in candidate["baselineComparisons"]:
            lines.append(
                f"    vs #{comparison['sequence']} {_short(comparison['payload'])}: "
                f"statusEqual={comparison['statusEqual']} "
                f"lengthEqual={comparison['lengthEqual']} bodyEqual={comparison['bodyEqual']}"
            )
    if report["truncated"]:
        lines.append("  Output truncated; use --limit 0 to show all selected candidates.")
    return "\n".join(lines)


def _signal_values(raw: str) -> tuple[str, ...]:
    values = tuple(value.strip().upper() for value in raw.split(",") if value.strip())
    if not values:
        raise argparse.ArgumentTypeError("at least one signal is required")
    return values


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="action", required=True)

    doctor = commands.add_parser("doctor", help="Locate and validate BypassFuzzer CLI")
    doctor.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    run = commands.add_parser("run", help="Run a compatible BypassFuzzer command unchanged")
    run.add_argument("cli_arguments", nargs=argparse.REMAINDER)

    triage = commands.add_parser("triage", help="Validate and summarize a schema-v1 evidence directory")
    triage.add_argument("output_directory", type=Path)
    group = triage.add_mutually_exclusive_group()
    group.add_argument(
        "--signals",
        type=_signal_values,
        default=None,
        help="Comma-separated signal filter",
    )
    group.add_argument("--all", action="store_true", help="Include every non-baseline record")
    triage.add_argument("--limit", type=int, default=50, help="Maximum candidates; 0 means unlimited")
    triage.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    return root


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.action == "doctor":
            result = validate_cli(resolve_cli())
            if arguments.json:
                print(json.dumps(result, sort_keys=True))
            else:
                print(
                    f"BypassFuzzer CLI {result['version']} PASS\n"
                    f"source={result['source']}\n"
                    f"commands={','.join(result['commands'])}"
                )
            return 0
        if arguments.action == "run":
            return run_cli(resolve_cli(), arguments.cli_arguments)
        if arguments.limit < 0:
            raise BypassFuzzerError("--limit must be zero or greater")
        report = build_triage_report(
            arguments.output_directory,
            signals=arguments.signals,
            include_all=arguments.all,
            limit=arguments.limit,
        )
        print(json.dumps(report, sort_keys=True) if arguments.json else render_triage_text(report))
        return 0
    except BypassFuzzerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
