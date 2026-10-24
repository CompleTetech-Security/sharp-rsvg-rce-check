"""Synthetic publication-boundary and portable CSV regressions."""
import contextlib
import inspect
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import sharp_rsvg_rce_check as c
VERSION_FIELD = 'unused'
FIXED = '0.35.5'

BASE_ARGS = ['--library-source', 'bundled', '--sharp-version', '0.35.5']

UNCERTAIN_ARGS = BASE_ARGS

class PublicationBoundaryTests(unittest.TestCase):
    def run_cli(self,*args):
        with contextlib.redirect_stdout(io.StringIO()) as out,contextlib.redirect_stderr(io.StringIO()) as err:
            try:code=c.main(list(args))
            except SystemExit as exc:code=exc.code
        return code,out.getvalue(),err.getvalue()
    def test_completed_atomic_operation_then_interrupt_is_never_repeated(self):
        for force,attribute in [(False,'link'),(True,'replace')]:
            with self.subTest(force=force),tempfile.TemporaryDirectory() as directory:
                target=Path(directory)/'report.json'
                if force:target.write_text('old')
                original=getattr(c.os,attribute);calls=[]
                def publish_then_interrupt(src,dst):
                    calls.append((src,dst));original(src,dst);raise KeyboardInterrupt
                with mock.patch.object(c.os,attribute,publish_then_interrupt):
                    code,_,_=self.run_cli(*BASE_ARGS,'--format','json','--output',str(target),*(['--force'] if force else []))
                self.assertEqual(130,code);self.assertEqual(1,len(calls))
                self.assertTrue(json.loads(target.read_text())['complete'])
                self.assertEqual(['report.json'],sorted(p.name for p in Path(directory).iterdir()))
    def test_interrupt_at_success_flag_assignment_is_guarded(self):
        lines,start=inspect.getsourcelines(c.save_report)
        atomic=max(i for i,line in enumerate(lines) if 'os.link(' in line or 'os.replace(' in line)
        flags=[i for i in range(atomic+1,len(lines)) if 'state["published"] = True' in lines[i]]
        self.assertTrue(flags,"Publisher must expose guarded success tracking")
        flag=start+flags[0]
        for force in [False,True]:
            with self.subTest(force=force),tempfile.TemporaryDirectory() as directory:
                target=Path(directory)/'report.json';seen=[]
                if force:target.write_text('old')
                def trace(frame,event,arg):
                    if frame.f_code is c.save_report.__code__ and event=='line' and frame.f_lineno==flag and not seen:
                        seen.append(True);sys.settrace(None);raise KeyboardInterrupt
                    return trace
                try:
                    sys.settrace(trace)
                    code,_,_=self.run_cli(*BASE_ARGS,'--format','json','--output',str(target),*(['--force'] if force else []))
                finally:sys.settrace(None)
                self.assertTrue(seen);self.assertEqual(130,code)
                self.assertTrue(json.loads(target.read_text())['complete'])
    def test_competing_identical_bytes_are_not_our_staged_inode(self):
        for force,attribute in [(False,'link'),(True,'replace')]:
            with self.subTest(force=force),tempfile.TemporaryDirectory() as directory:
                target=Path(directory)/'report.json';calls=[];original=getattr(c.os,attribute)
                def competitor(src,dst):
                    calls.append(True)
                    if len(calls)==1:
                        Path(dst).write_bytes(Path(src).read_bytes());raise KeyboardInterrupt
                    return original(src,dst)
                with mock.patch.object(c.os,attribute,competitor):
                    code,_,_=self.run_cli(*BASE_ARGS,'--format','json','--output',str(target),*(['--force'] if force else []))
                self.assertEqual(2,len(calls))
                self.assertEqual(130,code)
                self.assertEqual(not force,json.loads(target.read_text())['complete'])
    def test_indeterminate_publication_never_retries(self):
        for fmt in ['json', 'csv', 'html']:
            for force, attribute in [(False, 'link'), (True, 'replace')]:
                for failure in ['metadata', 'second_interrupt']:
                    with self.subTest(fmt=fmt, force=force, failure=failure), tempfile.TemporaryDirectory() as directory:
                        target = Path(directory) / ('report.' + fmt)
                        if force:
                            target.write_text('old')
                        original = getattr(c.os, attribute)
                        original_stat = c.os.stat
                        calls = []
                        committed = []
                        def publish(src, dst):
                            calls.append(True)
                            committed.append(Path(src).read_bytes())
                            original(src, dst)
                            raise KeyboardInterrupt
                        def stat(path, *args, **kwargs):
                            if kwargs.get('follow_symlinks') is False and Path(path) == target:
                                if failure == 'second_interrupt':
                                    raise KeyboardInterrupt
                                raise OSError(5, 'synthetic metadata failure')
                            return original_stat(path, *args, **kwargs)
                        with mock.patch.object(c.os, attribute, publish), mock.patch.object(c.os, 'stat', stat):
                            code, out, err = self.run_cli(*UNCERTAIN_ARGS, '--format', fmt, '--output', str(target), *(['--force'] if force else []))
                        self.assertEqual(130, code)
                        self.assertEqual('', out)
                        self.assertEqual(1, len(calls))
                        self.assertEqual(committed[0], target.read_bytes())
                        self.assertNotIn('Traceback', err)
                        self.assertNotIn('complete report was written', err)
                        if failure == 'metadata':
                            self.assertIn('indeterminate', err)
                        self.assertEqual([target.name], sorted(x.name for x in Path(directory).iterdir()))

    def test_definite_absence_allows_incomplete_recovery(self):
        for force, attribute in [(False, 'link'), (True, 'replace')]:
            with self.subTest(force=force), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / 'report.json'
                original = getattr(c.os, attribute)
                calls = []
                def publish(src, dst):
                    calls.append(True)
                    if len(calls) == 1:
                        raise KeyboardInterrupt
                    return original(src, dst)
                with mock.patch.object(c.os, attribute, publish):
                    code, _, _ = self.run_cli(*UNCERTAIN_ARGS, '--format', 'json', '--output', str(target), *(['--force'] if force else []))
                self.assertEqual(130, code)
                self.assertEqual(2, len(calls))
                self.assertFalse(json.loads(target.read_text())['complete'])

if __name__=='__main__':unittest.main()
