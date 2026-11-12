#!/usr/bin/env python3
"""Unit tests for the BypassFuzzer skill helper."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("bypassfuzzer.py")
SPEC = importlib.util.spec_from_file_location("bypassfuzzer_helper", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
bf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bf)


class ResolverTests(unittest.TestCase):
    def fake_cli(
        self,
        directory: Path,
        version: str = "1.4.4",
        exit_code: int = 0,
        commands: tuple[str, ...] = bf.COMMANDS,
        capture: Path | None = None,
        omitted_options: tuple[str, ...] = (),
    ) -> Path:
        path = directory / "bypassfuzzer"
        path.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "from pathlib import Path\n"
            f"version = {version!r}\n"
            f"commands = {commands!r}\n"
            f"options = {bf.REQUIRED_OPTIONS!r}\n"
            f"omitted_options = {omitted_options!r}\n"
            f"capture = {None if capture is None else str(capture)!r}\n"
            "if sys.argv[1:] == ['--version']:\n"
            "    print('BypassFuzzer CLI ' + version)\n"
            "elif sys.argv[1:] == ['--help']:\n"
            "    print('Commands: ' + ' '.join(commands))\n"
            "elif len(sys.argv) >= 3 and sys.argv[1] in commands and sys.argv[2] == '--help':\n"
            "    print('Usage: bypassfuzzer ' + sys.argv[1] + ' ' + ' '.join(option for option in options[sys.argv[1]] if option not in omitted_options))\n"
            "elif sys.argv[1:] and sys.argv[1] in commands:\n"
            "    if capture:\n"
            "        Path(capture).write_text(json.dumps(sys.argv[1:]))\n"
            f"    raise SystemExit({exit_code})\n"
            "else:\n"
            "    raise SystemExit(2)\n",
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path

    def test_environment_override_precedes_path(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            override_dir = root / "override"
            path_dir = root / "path"
            override_dir.mkdir()
            path_dir.mkdir()
            override = self.fake_cli(override_dir)
            self.fake_cli(path_dir)
            resolved = bf.resolve_cli(root, {"BYPASSFUZZER_CLI": str(override), "PATH": str(path_dir)})
            self.assertEqual(resolved, [str(override.resolve())])

    def test_path_precedes_source_jar(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path_dir = root / "path"
            path_dir.mkdir()
            executable = self.fake_cli(path_dir)
            jar = root / "cli/build/libs/bypassfuzzer-cli.jar"
            jar.parent.mkdir(parents=True)
            jar.touch()
            resolved = bf.resolve_cli(root, {"PATH": str(path_dir)})
            self.assertEqual(resolved, [str(executable.resolve())])

    def test_source_jar_is_found_from_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            jar = root / "cli/build/libs/bypassfuzzer-cli.jar"
            jar.parent.mkdir(parents=True)
            jar.touch()
            java_dir = root / "java-bin"
            java_dir.mkdir()
            java = java_dir / "java"
            java.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            java.chmod(0o755)
            child = root / "work/nested"
            child.mkdir(parents=True)
            resolved = bf.resolve_cli(child, {"PATH": str(java_dir)})
            self.assertEqual(resolved, [str(java.resolve()), "-jar", str(jar.resolve())])

    def test_validate_accepts_minimum_and_run_propagates_exit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            capture = root / "arguments.json"
            executable = self.fake_cli(root, exit_code=7, capture=capture)
            report = bf.validate_cli([str(executable)])
            self.assertEqual(report["version"], "1.4.4")
            self.assertEqual(bf.run_cli([str(executable)], ["bypass", "--example"]), 7)
            self.assertEqual(json.loads(capture.read_text()), ["bypass", "--example"])

    def test_validate_rejects_old_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            executable = self.fake_cli(Path(raw), version="1.4.3")
            with self.assertRaisesRegex(bf.BypassFuzzerError, "too old"):
                bf.validate_cli([str(executable)])

    def test_validate_preserves_development_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            executable = self.fake_cli(Path(raw), version="1.4.4-dev.10.g1234567")
            self.assertEqual(bf.validate_cli([str(executable)])["version"], "1.4.4-dev.10.g1234567")

    def test_results_runs_unchanged_and_preserves_exit_status(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            capture = root / "arguments.json"
            executable = self.fake_cli(root, exit_code=3, capture=capture)
            arguments = ["results", "--input", "evidence/run", "--format", "jsonl", "--response-regex"]
            self.assertEqual(bf.run_cli([str(executable)], arguments), 3)
            self.assertEqual(json.loads(capture.read_text()), arguments)

    def test_doctor_rejects_stale_openapi_surface(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            executable = self.fake_cli(Path(raw), omitted_options=("--openapi-variable",))
            with self.assertRaisesRegex(bf.BypassFuzzerError, "sweep lacks options: --openapi-variable"):
                bf.validate_cli([str(executable)])

    def test_validate_rejects_missing_command(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            executable = self.fake_cli(
                Path(raw), commands=("sweep", "bypass", "idor")
            )
            with self.assertRaisesRegex(bf.BypassFuzzerError, "lacks commands"):
                bf.validate_cli([str(executable)])

    def test_invalid_override_does_not_fall_through(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            missing = Path(raw) / "missing.jar"
            with self.assertRaisesRegex(bf.BypassFuzzerError, "does not exist"):
                bf.resolve_cli(Path(raw), {"BYPASSFUZZER_CLI": str(missing), "PATH": ""})

    def test_resolution_failure_has_setup_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with mock.patch.object(bf, "__file__", str(Path(raw) / "standalone/scripts/bypassfuzzer.py")):
                with self.assertRaisesRegex(bf.BypassFuzzerError, "BYPASSFUZZER_CLI"):
                    bf.resolve_cli(Path(raw), {"PATH": ""})

    def test_owning_checkout_is_found_from_an_external_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repository"
            jar = repo / "cli/build/libs/bypassfuzzer-cli.jar"
            jar.parent.mkdir(parents=True)
            jar.touch()
            java = root / "java"
            java.write_text("#!/bin/sh\nexit 0\n")
            java.chmod(0o755)
            workspace = root / "engagement"
            workspace.mkdir()
            with mock.patch.object(bf, "__file__", str(repo / ".agents/skills/bypassfuzzer-cli/scripts/bypassfuzzer.py")):
                self.assertEqual(bf.resolve_cli(workspace, {"PATH": str(root)}),
                                 [str(java), "-jar", str(jar)])


class TriageTests(unittest.TestCase):
    def record(
        self,
        sequence: int,
        payload: str,
        signal: str,
        status: int,
        body: bytes,
        baseline: bool,
    ) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "runId": "run-1",
            "sequence": sequence,
            "mode": "idor",
            "target": "GET https://example.test/objects/alice",
            "protocol": "http1",
            "family": "Control" if baseline else "idor.path.suffix_formats",
            "payload": payload,
            "encoding": "",
            "baseline": baseline,
            "signal": signal,
            "retryAttempt": 0,
            "requestRef": f"requests/{sequence:06d}-request.raw",
            "responseRef": f"responses/{sequence:06d}-response.raw",
            "status": status,
            "length": len(body),
            "durationMillis": sequence,
            "error": None,
        }

    def fixture(self, root: Path) -> list[dict[str, object]]:
        (root / "requests").mkdir()
        (root / "responses").mkdir()
        rows = [
            self.record(1, "idor.baseline.control", "BASELINE", 200, b"authorized", True),
            self.record(2, "idor.baseline.target", "BASELINE", 403, b"denied", True),
            self.record(3, "variant-success", "LIKELY_BYPASS", 200, b"authorized", False),
            self.record(4, "variant-denied", "RESPONSE_CHANGED", 403, b"denied", False),
            self.record(5, "variant-quiet", "NO_SIGNAL", 403, b"denied", False),
        ]
        bodies = [b"authorized", b"denied", b"authorized", b"denied", b"denied"]
        for row, body in zip(rows, bodies):
            sequence = int(row["sequence"])
            (root / str(row["requestRef"])).write_bytes(b"GET / HTTP/1.1\r\n\r\n")
            (root / str(row["responseRef"])).write_bytes(
                f"HTTP/1.1 {row['status']}\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
            )
        (root / "run.json").write_text(
            json.dumps({"schemaVersion": 1, "runId": "run-1"}), encoding="utf-8"
        )
        (root / "summary.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "state": "completed",
                    "mode": "idor",
                    "records": len(rows),
                    "findings": 1,
                    "throttled": 0,
                    "transportErrors": 0,
                }
            ),
            encoding="utf-8",
        )
        (root / "results.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        return rows

    def test_triage_filters_and_compares_both_idor_baselines(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.fixture(root)
            report = bf.build_triage_report(root)
            self.assertEqual(len(report["baselines"]), 2)
            self.assertEqual(report["candidateCount"], 2)
            success = report["candidates"][0]
            denied = report["candidates"][1]
            self.assertTrue(success["baselineComparisons"][0]["bodyEqual"])
            self.assertFalse(success["baselineComparisons"][1]["bodyEqual"])
            self.assertFalse(denied["baselineComparisons"][0]["bodyEqual"])
            self.assertTrue(denied["baselineComparisons"][1]["bodyEqual"])

    def test_all_and_limit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.fixture(root)
            report = bf.build_triage_report(root, include_all=True, limit=1)
            self.assertEqual(report["candidateCount"], 3)
            self.assertEqual(report["displayedCandidateCount"], 1)
            self.assertTrue(report["truncated"])

    def test_default_triage_includes_current_idor_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            rows = self.fixture(root)
            rows[2]["signal"] = "IDOR_CANDIDATE"
            rows[3]["signal"] = "MASS_ASSIGNMENT_CANDIDATE"
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
            report = bf.build_triage_report(root)
            self.assertEqual([row["signal"] for row in report["candidates"]],
                             ["IDOR_CANDIDATE", "MASS_ASSIGNMENT_CANDIDATE"])

    def test_sweep_descriptive_signals_are_visible_unless_explicitly_filtered(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            rows = self.fixture(root)
            for row in rows:
                row["mode"] = "sweep"
            rows[2]["signal"] = "403 -> 200"
            rows[3]["signal"] = "Content-Type text/html -> application/json"
            rows[4]["signal"] = ""
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
            self.assertEqual(bf.build_triage_report(root)["candidateCount"], 2)
            self.assertEqual(bf.build_triage_report(root, signals=("THROTTLED",))["candidateCount"], 0)

    def test_report_is_json_serializable_without_raw_bodies(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.fixture(root)
            encoded = json.dumps(bf.build_triage_report(root))
            self.assertIn('"bodySha256"', encoded)
            self.assertNotIn('"authorized"', encoded)
            self.assertNotIn('"denied"', encoded)

    def test_render_does_not_print_response_body(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.fixture(root)
            text = bf.render_triage_text(bf.build_triage_report(root))
            self.assertNotIn("authorized\n", text)
            self.assertNotIn("denied\n", text)
            self.assertIn("bodyEqual=True", text)

    def test_rejects_reference_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            rows = self.fixture(root)
            rows[2]["requestRef"] = "../secret.raw"
            (root / "results.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )
            with self.assertRaisesRegex(bf.BypassFuzzerError, "escapes"):
                bf.build_triage_report(root)

    def test_rejects_missing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.fixture(root)
            (root / "requests/000003-request.raw").unlink()
            with self.assertRaisesRegex(bf.BypassFuzzerError, "does not exist"):
                bf.build_triage_report(root)

    def test_rejects_schema_and_count_mismatches(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.fixture(root)
            summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            summary["records"] = 99
            (root / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            with self.assertRaisesRegex(bf.BypassFuzzerError, "record count"):
                bf.build_triage_report(root)

    def test_rejects_schema_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.fixture(root)
            summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            summary["schemaVersion"] = 2
            (root / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            with self.assertRaisesRegex(bf.BypassFuzzerError, "schemaVersion"):
                bf.build_triage_report(root)

    def test_rejects_run_id_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            rows = self.fixture(root)
            rows[3]["runId"] = "another-run"
            (root / "results.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )
            with self.assertRaisesRegex(bf.BypassFuzzerError, "runId"):
                bf.build_triage_report(root)


if __name__ == "__main__":
    unittest.main()
