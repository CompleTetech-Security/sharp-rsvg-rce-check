"""Synthetic run-envelope provenance regressions; no networking."""
import contextlib
import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import sharp_rsvg_rce_check as c

STAMP = '2026-10-25T12:34:56Z'
DIGEST = 'a' * 64
BASE = ['--sharp-version', '0.35.4', '--library-source', 'bundled', '--sharp-build-source', 'upstream']


class ProvenanceTests(unittest.TestCase):
    def report(self, results=(), **extra):
        return c.make_report(c.TOOL_NAME, c.TOOL_VERSION, c.SNAPSHOT_ID, c.RULE_DATE,
                             list(results), snapshot_digest=c.snapshot_digest(c.RULE_SNAPSHOT),
                             generated_at=STAMP, executable_sha256=DIGEST, **extra)

    def test_injected_context_deterministic_and_preserved_all_formats(self):
        record = c.normalize_record({'asset_id': 'synthetic', 'sharp_versions': ['0.35.4'],
                                     'library_source': 'bundled', 'sharp_build_source': 'upstream'})
        report = self.report([c.assess_record(record)])
        self.assertEqual(c.canonical_json(report), c.canonical_json(self.report(report['results'])))
        row = next(csv.DictReader(io.StringIO(c.render_csv(report))))
        expected = dict(tool=c.TOOL_NAME, tool_version=c.TOOL_VERSION, executable_sha256=DIGEST,
                        generated_at=STAMP, rules_snapshot_id=c.SNAPSHOT_ID,
                        rules_sha256=c.snapshot_digest(c.RULE_SNAPSHOT), rules_as_of=c.RULE_DATE)
        for key, value in expected.items():
            self.assertEqual(value, row[key])
            self.assertIn(value, c.render_html(report))
        self.assertEqual('not_tested', row['exploitability'])

    def test_empty_incomplete_and_formula_safe_summary(self):
        report = self.report(complete=False)
        report['tool']['version'] = '=synthetic'
        row = next(csv.DictReader(io.StringIO(c.render_csv(report))))
        self.assertEqual('summary', row['record_type'])
        self.assertEqual('False', row['complete'])
        self.assertEqual("'=synthetic", row['tool_version'])
        self.assertEqual(STAMP, row['generated_at'])
        self.assertEqual(DIGEST, row['executable_sha256'])
        self.assertIn('Incomplete assessment', c.render_html(report))

    def test_real_timestamp_and_digest_validation(self):
        external = json.loads((Path(c.__file__).parent / 'schemas/report-v1.schema.json').read_text(encoding='utf-8'))
        external.pop('$schema')
        external.pop('$id')
        external.pop('title')
        self.assertEqual(c.REPORT_SCHEMA, external)
        for value in ['2026-02-30T12:00:00Z', '2026-10-25T12:00:00+00:00', STAMP+'\n']:
            report = self.report()
            report['generated_at'] = value
            with self.assertRaises(c.ContractError):
                c.validate_report(report)
        report = self.report()
        report['tool']['executable_sha256'] = 'private-invalid'
        with self.assertRaises(c.ContractError):
            c.validate_report(report)

    def test_cli_context_captured_once_and_reused_after_interrupt(self):
        for fmt in ['json', 'csv', 'html']:
            stdout, stderr = io.StringIO(), io.StringIO()
            real = c.canonical_json if fmt == 'json' else c.render_csv if fmt == 'csv' else c.render_html
            name = 'canonical_json' if fmt == 'json' else 'render_csv' if fmt == 'csv' else 'render_html'
            calls = []
            def render(report, *args, **kwargs):
                calls.append(report)
                if len(calls) == 1:
                    raise KeyboardInterrupt
                return real(report, *args, **kwargs)
            with patch.object(c, 'utc_now', return_value=STAMP) as clock, patch.object(c, 'executable_digest', return_value=DIGEST) as digest, patch.object(c, name, side_effect=render), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(130, c.main(BASE + ['--format', fmt]))
            self.assertEqual(1, clock.call_count)
            self.assertEqual(1, digest.call_count)
            self.assertEqual([STAMP, STAMP], [r['generated_at'] for r in calls])
            self.assertFalse(calls[-1]['complete'])
            self.assertEqual(1, len(calls[-1]['results']))
            self.assertIn(STAMP, stdout.getvalue())

    def test_cli_digest_identifies_standalone_bytes(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(0, c.main(BASE))
        report = json.loads(stdout.getvalue())
        self.assertEqual(hashlib.sha256(Path(c.__file__).read_bytes()).hexdigest(), report['tool']['executable_sha256'])
        self.assertRegex(report['generated_at'], r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')

    def test_copied_and_symlink_invocations_hash_actual_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / 'copied.py'
            copied.write_bytes(Path(c.__file__).read_bytes() + b'\n# synthetic installation copy\n')
            result = subprocess.run([sys.executable, str(copied), *BASE], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            expected = hashlib.sha256(copied.read_bytes()).hexdigest()
            self.assertEqual(expected, json.loads(result.stdout)['tool']['executable_sha256'])
            linked = Path(directory) / 'linked.py'
            try:
                linked.symlink_to(copied)
            except OSError:
                self.skipTest('Symlink creation unavailable on this platform')
            result = subprocess.run([sys.executable, str(linked), *BASE], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(expected, json.loads(result.stdout)['tool']['executable_sha256'])
            # Executable aliases are supported without allowing evidence aliases.
            with self.assertRaises(c.ContractError):
                c._read_regular_file(linked, c.MAX_JSON_BYTES)


if __name__ == '__main__':
    unittest.main()
