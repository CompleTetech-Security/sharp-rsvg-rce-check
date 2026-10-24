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
if __name__=='__main__':unittest.main()
