"""Publication fixtures exercise IO only; no qualification claim or model call."""
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('qualification_publisher',Path(__file__).resolve().parents[1]/'scripts/model_qualification.py')
publisher=importlib.util.module_from_spec(spec);spec.loader.exec_module(publisher)

class QualificationPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.output=self.root/'fixture.json'
        self.payload=b'{"fixture_only":true}'

    def validate(self,path):
        self.assertEqual(path.read_bytes(),self.payload)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)

    def test_success_handles_short_writes_and_syncs_parent(self):
        original_write=os.write;syncs=[];original_sync=os.fsync
        def short_write(fd,data):return original_write(fd,data[:max(1,len(data)//2)])
        def sync(fd):syncs.append(stat.S_ISDIR(os.fstat(fd).st_mode));return original_sync(fd)
        with patch.object(publisher.os,'write',side_effect=short_write),patch.object(publisher.os,'fsync',side_effect=sync):
            publisher.publish_receipt(self.output,self.payload,self.validate)
        self.assertTrue(any(syncs));self.validate(self.output)
        self.assertEqual(list(self.root.iterdir()),[self.output])

    def test_pending_validation_failure_never_publishes_final(self):
        def reject(path):raise ValueError('fixture rejection')
        with self.assertRaises(ValueError):publisher.publish_receipt(self.output,self.payload,reject)
        self.assertFalse(self.output.exists());self.assertEqual(list(self.root.iterdir()),[])

    def test_postpublication_validation_failure_removes_final(self):
        def reject_final(path):
            if path.name==self.output.name:raise ValueError('fixture changed identity')
            self.validate(path)
        with self.assertRaises(ValueError):publisher.publish_receipt(self.output,self.payload,reject_final)
        self.assertEqual(list(self.root.iterdir()),[])

    def test_existing_destination_is_not_overwritten(self):
        self.output.write_bytes(b'untouched')
        with self.assertRaises(FileExistsError):publisher.publish_receipt(self.output,self.payload,self.validate)
        self.assertEqual(self.output.read_bytes(),b'untouched')
        self.assertEqual(list(self.root.iterdir()),[self.output])

    def test_shared_parent_rejected_without_chmod(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'owner-only'):publisher.publish_receipt(self.output,self.payload,self.validate)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode),0o755)
        self.assertFalse(self.output.exists())
