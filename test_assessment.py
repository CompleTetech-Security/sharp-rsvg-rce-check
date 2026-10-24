# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Synthetic offline evidence, boundary and CLI behavior regressions."""
import contextlib
import csv
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import sharp_rsvg_rce_check as check


def bundled(version="0.35.4", **changes):
    return {"asset_id": "synthetic-1", "library_source": "bundled",
            "sharp_versions": [version], "sharp_build_source": "upstream", **changes}


def global_library(version="2.63.2", **changes):
    return {"asset_id": "synthetic-1", "library_source": "global",
            "librsvg_versions": [version], "librsvg_build_source": "upstream", **changes}


def run_cli(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = check.main(args)
    return code, out.getvalue(), err.getvalue()


class AssessmentTests(unittest.TestCase):
    def test_bundled_boundaries(self):
        for version in ("0.0.0", "0.34.5", "0.35.0", "0.35.4"):
            with self.subTest(version=version):
                result = check.assess_record(bundled(version))
                self.assertEqual("potentially_affected", result["status"])
                self.assertEqual("affected", result["version_assessment"])
        for version in ("0.35.5", "0.35.6"):
            with self.subTest(version=version):
                self.assertEqual("fixed_version_reported", check.assess_record(bundled(version))["status"])

    def test_uncovered_and_qualified_versions_stay_unknown(self):
        for value in ("0.36.0", "1.0.0", "v0.35.5", "0.35", "00.35.5", "0.35.5-rc.1", "0.35.5+vendor", "^0.35.5", " 0.35.5", "０.35.5", "9" * 64):
            with self.subTest(value=value):
                self.assertEqual("unknown", check.assess_record(bundled(value))["status"])

    def test_unknown_or_modified_builds_are_not_cleared(self):
        for source in ("unknown", "vendor", "custom"):
            for version in ("0.35.4", "0.35.5"):
                with self.subTest(source=source, version=version):
                    self.assertEqual("unknown", check.assess_record(bundled(version, sharp_build_source=source))["status"])
            self.assertEqual("unknown", check.assess_record(global_library(librsvg_build_source=source))["status"])

    def test_conflicts_preserved_while_equal_observations_agree(self):
        result = check.assess_record(bundled(sharp_versions=["0.35.4", "0.35.5"]))
        self.assertEqual("unknown", result["status"])
        self.assertIsNone(result["component"]["version"])
        self.assertEqual("conflicting", result["evidence"][0]["state"])
        self.assertEqual("fixed_version_reported", check.assess_record(bundled(sharp_versions=["0.35.5", "0.35.5"]))["status"])

    def test_patched_sharp_cannot_clear_unknown_or_global_linkage(self):
        record = bundled("0.35.5", library_source="unknown")
        self.assertEqual("unknown", check.assess_record(record)["status"])
        record["library_source"] = "global"
        self.assertEqual("unknown", check.assess_record(record)["status"])
        record.update(librsvg_versions=["2.63.1"], librsvg_build_source="upstream")
        self.assertEqual("unknown", check.assess_record(record)["status"])
        record["librsvg_versions"] = ["2.63.2"]
        result = check.assess_record(record)
        self.assertEqual("fixed_version_reported", result["status"])
        self.assertEqual("2.63.2", result["component"]["version"])
        self.assertIn("global", result["component"]["name"])

    def test_global_remediation_only_with_independent_exact_evidence(self):
        for version in ("2.63.2", "2.63.3"):
            with self.subTest(version=version):
                self.assertEqual("fixed_version_reported", check.assess_record(global_library(version))["status"])
        for version in ("2.62.0", "2.63.1", "2.64.0", "3.0.0", "2.63.2-vendor", "2.63.2+backport"):
            with self.subTest(version=version):
                result = check.assess_record(global_library(version))
                self.assertEqual("unknown", result["status"])
                self.assertEqual("unknown", result["version_assessment"])
        result = check.assess_record(global_library(librsvg_versions=["2.63.1", "2.63.2"]))
        self.assertEqual("unknown", result["status"])

    def test_additional_native_observations_cannot_hide_bundle_mismatch(self):
        for sharp, rsvg in (("0.35.4", "2.63.2"), ("0.35.5", "2.63.1")):
            result = check.assess_record(bundled(sharp, librsvg_versions=[rsvg], librsvg_build_source="upstream"))
            self.assertEqual("unknown", result["status"])
        self.assertEqual("fixed_version_reported", check.assess_record(bundled("0.35.5", librsvg_versions=["2.63.2"], librsvg_build_source="upstream"))["status"])
        self.assertEqual("unknown", check.assess_record(bundled("0.35.5", librsvg_versions=["2.63.2"]))["status"])
        self.assertEqual("unknown", check.assess_record(global_library(sharp_versions=["0.35.4", "0.35.5"]))["status"])

    def test_missing_platform_or_hardening_never_becomes_a_safety_result(self):
        result = check.assess_record(bundled())
        self.assertEqual("potentially_affected", result["status"])
        states = {item["id"]: item["state"] for item in result["preconditions"]}
        self.assertEqual("unknown", states["glibc-linux"])
        self.assertEqual("unknown", states["node-without-pie"])
        self.assertEqual("unknown", result["mitigation"]["state"])

    def test_all_reported_conditions_do_not_assert_exploitability(self):
        result = check.assess_record(bundled(platform="linux", libc="glibc", node_pie="disabled", svg_decoder="enabled", untrusted_svg="present"))
        self.assertEqual("precondition_present", result["status"])
        self.assertEqual("not_tested", result["exploitability"])
        self.assertEqual("not_tested", result["reachability"]["state"])
        self.assertEqual("unknown", result["threat"]["kev"]["state"])

    def test_other_platform_or_no_input_does_not_clear_memory_bug(self):
        for changes in ({"platform": "other"}, {"platform": "linux", "libc": "musl"}, {"untrusted_svg": "absent"}):
            result = check.assess_record(bundled(**changes))
            self.assertEqual("potentially_affected", result["status"])
            self.assertEqual("affected", result["version_assessment"])

    def test_decoder_block_and_pie_are_separate_mitigations_not_patches(self):
        for changes, expected in (({"svg_decoder": "blocked"}, "svg-block"), ({"node_pie": "enabled"}, "node-pie")):
            with self.subTest(changes=changes):
                result = check.assess_record(bundled(**changes))
                self.assertEqual("mitigated_configuration", result["status"])
                self.assertEqual("affected", result["version_assessment"])
                self.assertEqual([expected], result["mitigation"]["evidence_ids"])
                self.assertEqual("not_tested", result["exploitability"])
        result = check.assess_record(bundled(node_pie="conflicting", svg_decoder="conflicting"))
        self.assertEqual("potentially_affected", result["status"])
        self.assertEqual("unknown", result["mitigation"]["state"])

    def test_mitigation_does_not_resolve_unknown_version(self):
        result = check.assess_record({"asset_id": "synthetic-1", "node_pie": "enabled", "svg_decoder": "blocked"})
        self.assertEqual("unknown", result["status"])
        self.assertEqual("observed", result["mitigation"]["state"])

    def test_unrecognized_version_text_is_not_echoed(self):
        secret = "synthetic-private-value"
        result = check.assess_record(bundled(secret))
        self.assertNotIn(secret, json.dumps(result))


class InventoryTests(unittest.TestCase):
    def read(self, value):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.json"
            path.write_text(value, encoding="utf-8")
            return check.read_inventory(path)

    def test_small_valid_record_preserves_unknown_defaults(self):
        records = self.read(json.dumps({"schema_version": "1.0", "records": [{"asset_id": "synthetic-1"}]}))
        self.assertEqual("unknown", records[0]["libc"])
        self.assertEqual("unknown", check.assess_record(records[0])["status"])

    def test_duplicate_keys_and_nonfinite_json_rejected(self):
        for text in ('{"schema_version":"1.0","schema_version":"1.0","records":[]}', '{"x":NaN}', '{"x":1e999}', '{"x":Infinity}', '[1]', 'null'):
            with self.subTest(text=text), self.assertRaises(check.ContractError):
                self.read(text)

    def test_ambiguous_or_excessive_records_rejected(self):
        for record in (bundled(sharp_versions=["0.35.5"] * 9), bundled(sharp_versions="0.35.5"), bundled(extra="unexpected"), bundled(node_pie=True), bundled(asset_id="=FORMULA()"), bundled(sharp_versions=["x" * 65])):
            with self.subTest(record=record), self.assertRaises(check.ContractError):
                self.read(json.dumps({"schema_version": "1.0", "records": [record]}))
        for records in ([], [bundled(), bundled()], [{"asset_id": "x"}] * (check.MAX_RECORDS + 1)):
            with self.subTest(count=len(records)), self.assertRaises(check.ContractError):
                self.read(json.dumps({"schema_version": "1.0", "records": records}))

    def test_oversized_file_rejected_before_json_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            with path.open("wb") as stream:
                stream.truncate(check.MAX_JSON_BYTES + 1)
            with self.assertRaises(check.ContractError):
                check.read_inventory(path)

    def test_symlink_inventory_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target, alias = Path(directory) / "target.json", Path(directory) / "alias.json"
            target.write_text(json.dumps({"schema_version": "1.0", "records": [bundled()]}))
            try:
                alias.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink unavailable")
            with self.assertRaises(check.ContractError):
                check.read_inventory(alias)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO unavailable")
    def test_fifo_rejected_without_opening_or_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fifo"
            os.mkfifo(path)
            with patch.object(check.os, "open", side_effect=AssertionError("must not open FIFO")):
                with self.assertRaises(check.ContractError):
                    check.read_inventory(path)


class CliTests(unittest.TestCase):
    BASE = ["--sharp-version", "0.35.4", "--library-source", "bundled", "--sharp-build-source", "upstream"]

    def test_findings_and_unknown_gates(self):
        self.assertEqual(0, run_cli(self.BASE)[0])
        self.assertEqual(1, run_cli(self.BASE + ["--fail-on-finding"])[0])
        self.assertEqual(1, run_cli(self.BASE + ["--fail-on-unknown"])[0])
        self.assertEqual(1, run_cli(self.BASE + ["--node-pie", "enabled", "--fail-on-finding"])[0])
        self.assertEqual(1, run_cli(["--sharp-version", "0.35.5", "--fail-on-unknown"])[0])
        self.assertEqual(0, run_cli(["--sharp-version", "0.35.5", "--library-source", "bundled", "--sharp-build-source", "upstream", "--fail-on-unknown"])[0])

    def test_inventory_and_per_asset_options_cannot_mix_even_defaults(self):
        for args in ([], ["--inventory", "synthetic.json", "--library-source", "unknown"], ["--inventory", "synthetic.json", "--asset-id", "asset-0001"]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                check.main(args)
            self.assertEqual(2, exc.exception.code)

    def test_output_no_clobber_and_input_alias_protection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "inventory.json"
            original = json.dumps({"schema_version": "1.0", "records": [bundled()]})
            source.write_text(original)
            output = root / "report.json"
            output.write_text("previous evidence")
            self.assertEqual(2, run_cli(self.BASE + ["--output", str(output)])[0])
            self.assertEqual("previous evidence", output.read_text())
            self.assertEqual(0, run_cli(self.BASE + ["--output", str(output), "--force"])[0])
            self.assertEqual(2, run_cli(["--inventory", str(source), "--output", str(source), "--force"])[0])
            self.assertEqual(original, source.read_text())
            alias = root / "alias.json"
            os.link(source, alias)
            self.assertEqual(2, run_cli(["--inventory", str(source), "--output", str(alias), "--force"])[0])
            self.assertEqual(original, alias.read_text())

    def test_partial_interrupt_retains_only_completed_results(self):
        first = check.assess_record(bundled())
        with patch.object(check, "read_inventory", return_value=[bundled(), bundled(asset_id="synthetic-2")]), patch.object(check, "assess_record", side_effect=[first, KeyboardInterrupt()]):
            code, output, error = run_cli(["--inventory", "synthetic.json"])
        report = json.loads(output)
        self.assertEqual(130, code)
        self.assertFalse(report["complete"])
        self.assertEqual(["synthetic-1"], [r["asset_id"] for r in report["results"]])
        self.assertIn("incomplete", error)

    def test_empty_interrupt_csv_retains_summary(self):
        with patch.object(check, "read_inventory", side_effect=KeyboardInterrupt()):
            code, output, _ = run_cli(["--inventory", "synthetic.json", "--format", "csv"])
        rows = list(csv.DictReader(io.StringIO(output)))
        self.assertEqual(130, code)
        self.assertEqual("summary", rows[0]["record_type"])
        self.assertEqual("False", rows[0]["complete"])

    def test_interrupted_partial_stdout_never_appends_another_report(self):
        class PartialSink:
            def __init__(self):
                self.calls = 0
                self.prefix = ""

            def write(self, text):
                self.calls += 1
                self.prefix += text[:32]
                raise KeyboardInterrupt

        sink = PartialSink()
        error = io.StringIO()
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(error):
            code = check.main(self.BASE)
        self.assertEqual(130, code)
        self.assertEqual(1, sink.calls)
        self.assertEqual(32, len(sink.prefix))
        self.assertIn("no second report", error.getvalue())

    def test_controlled_errors_do_not_echo_input_paths(self):
        code, _, error = run_cli(["--inventory", "/synthetic-private-directory/secret.json"])
        self.assertEqual(2, code)
        self.assertNotIn("synthetic-private-directory", error)

    def test_html_escapes_brand_and_requires_raster_logo(self):
        code, output, _ = run_cli(self.BASE + ["--format", "html", "--brand", '<script>alert("synthetic")</script>'])
        self.assertEqual(0, code)
        self.assertNotIn("<script>", output)
        self.assertIn("&lt;script&gt;", output)
        self.assertNotIn('<img src="http', output)
        self.assertEqual(2, run_cli(self.BASE + ["--logo", "missing.png"])[0])

    def test_offline_path_cannot_open_network_or_run_applications(self):
        with patch("socket.create_connection", side_effect=AssertionError("network forbidden")), patch("subprocess.Popen", side_effect=AssertionError("execution forbidden")):
            self.assertEqual(0, run_cli(self.BASE)[0])

    def test_copied_single_file_runs_without_companion_files(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "standalone.py"
            shutil.copyfile(check.__file__, script)
            result = subprocess.run([sys.executable, "-I", str(script), *self.BASE], cwd=directory, capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("potentially_affected", json.loads(result.stdout)["results"][0]["status"])
            original = script.read_bytes()
            result = subprocess.run([sys.executable, "-I", str(script), *self.BASE, "--output", str(script), "--force"], cwd=directory, capture_output=True, text=True, timeout=10)
            self.assertEqual(2, result.returncode)
            self.assertEqual(original, script.read_bytes())

    def test_snapshot_and_published_schemas_match_runtime_contract(self):
        root = Path(__file__).parent
        snapshot = json.loads((root / "rules/snapshot.json").read_text())
        check.validate_snapshot(snapshot)
        self.assertEqual(snapshot, check.RULE_SNAPSHOT)
        self.assertEqual(check.RULE_DATE, snapshot["created_at"])
        self.assertEqual(check.SNAPSHOT_ID, snapshot["snapshot_id"])
        schema = json.loads((root / "schemas/inventory-v1.schema.json").read_text())
        schema.pop("$schema")
        self.assertEqual(check.INPUT_SCHEMA, schema)


if __name__ == "__main__":
    unittest.main()
