"""Offline conflict retention across public report formats."""
import contextlib
import csv
import io
import json
import unittest
from unittest.mock import patch

import sharp_rsvg_rce_check as check


class ConflictEvidenceTests(unittest.TestCase):
    def report(self, sharp, native, fmt):
        args = ['--library-source', 'global' if native else 'bundled',
                '--sharp-build-source', 'upstream', '--librsvg-build-source', 'upstream',
                '--format', fmt]
        for value in sharp:
            args += ['--sharp-version', value]
        for value in native:
            args += ['--librsvg-version', value]
        out = io.StringIO()
        with patch('socket.socket', side_effect=AssertionError('offline')), contextlib.redirect_stdout(out):
            self.assertEqual(0, check.main(args))
        return out.getvalue()

    def test_both_components_retain_distinct_conflicts_in_all_formats(self):
        for fmt in ('json', 'csv', 'html'):
            with self.subTest(format=fmt):
                text = self.report(['0.35.4', '0.35.5'], ['2.63.1', '2.63.2'], fmt)
                for observation in ('Sharp version observation:', 'librsvg version observation:',
                                    '0.35.4, 0.35.5', '2.63.1, 2.63.2'):
                    self.assertIn(observation, text)
                if fmt == 'json':
                    result = json.loads(text)['results'][0]
                elif fmt == 'csv':
                    result = next(csv.DictReader(io.StringIO(text)))
                else:
                    self.assertIn('unknown', text)
                    self.assertIn('not_tested', text)
                    continue
                self.assertEqual('unknown', result['status'])
                self.assertEqual('not_tested', result['exploitability'])
                if fmt == 'json':
                    self.assertIsNone(result['component']['version'])

    def test_different_conflicting_pairs_are_distinguishable(self):
        for fmt in ('json', 'csv', 'html'):
            with self.subTest(format=fmt):
                self.assertNotEqual(self.report(['0.35.4', '0.35.5'], [], fmt),
                                    self.report(['0.35.3', '0.35.6'], [], fmt))
                self.assertNotEqual(self.report([], ['2.63.1', '2.63.2'], fmt),
                                    self.report([], ['2.63.0', '2.63.3'], fmt))

    def test_qualified_or_secret_bearing_values_are_not_echoed(self):
        unsafe = ['0.35.5+private-secret', '<private-secret>', '=private-secret']
        for fmt in ('json', 'csv', 'html'):
            with self.subTest(format=fmt):
                text = self.report(['0.35.4'] + unsafe, ['2.63.2'] + unsafe, fmt)
                self.assertIn('0.35.4', text)
                self.assertIn('2.63.2', text)
                self.assertNotIn('private-secret', text)
                self.assertIn('unknown', text)
                self.assertIn('not_tested', text)

    def test_duplicate_and_reordered_observations_have_stable_evidence(self):
        for fmt in ('json', 'csv', 'html'):
            with self.subTest(format=fmt):
                self.assertEqual(self.report(['0.35.5', '0.35.4', '0.35.4'], [], fmt),
                                 self.report(['0.35.4', '0.35.5'], [], fmt))

    def test_maximum_observations_preserve_bounded_validated_evidence(self):
        versions = ['0.35.' + str(i) for i in range(8)]
        result = check.assess_record({'asset_id': 'bounded', 'sharp_versions': versions})
        check.validate_result(result)
        detail = next(item['detail'] for item in result['evidence'] if item['id'] == 'sharp-versions')
        for version in versions:
            self.assertIn(version, detail)
        self.assertLess(len(detail), 2048)


if __name__ == '__main__':
    unittest.main()
