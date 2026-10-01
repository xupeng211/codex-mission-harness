"""Evidence destination hardening must never chmod unrelated ancestors."""
import os
import contextlib
import io
from unittest.mock import patch
from types import SimpleNamespace
import stat
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import deepseek_review as review


class EvidenceDirectoryModes(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.repo=self.root/'repo';self.repo.mkdir()
        self.parent=self.root/'shared';self.parent.mkdir();self.parent.chmod(0o750)
        self.evidence=self.parent/'evidence'

    def mode(self,path):return stat.S_IMODE(path.stat().st_mode)

    def test_new_destination_preserves_safe_existing_ancestor(self):
        _,fd=review.open_private_directory(self.evidence,self.repo)
        os.close(fd)
        self.assertEqual(self.mode(self.parent),0o750)
        self.assertEqual(self.mode(self.evidence),0o700)

    def test_writable_ancestor_rejected_without_permission_or_child_mutation(self):
        self.parent.chmod(0o775)
        with self.assertRaisesRegex(ValueError,'ancestor'):
            review.open_private_directory(self.evidence,self.repo)
        self.assertEqual(self.mode(self.parent),0o775)
        self.assertFalse(self.evidence.exists())

    def test_only_explicit_destination_may_be_hardened_when_creating(self):
        self.evidence.mkdir();self.evidence.chmod(0o755)
        _,fd=review.open_private_directory(self.evidence,self.repo);os.close(fd)
        self.assertEqual(self.mode(self.parent),0o750)
        self.assertEqual(self.mode(self.evidence),0o700)

    def test_read_only_validation_never_hardens_existing_destination(self):
        self.evidence.mkdir();self.evidence.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'owner-only'):
            review.open_private_directory(self.evidence,self.repo,create=False)
        self.assertEqual(self.mode(self.parent),0o750)
        self.assertEqual(self.mode(self.evidence),0o755)

    def test_cli_receipt_validation_never_chmods_shared_destination(self):
        self.evidence.mkdir();self.evidence.chmod(0o755)
        receipt=self.evidence/'invalid.json';receipt.write_text('{}');receipt.chmod(0o600)
        argv=['deepseek_review.py','validate','--receipt',str(receipt),'--repo',str(self.repo),
              '--base','a'*40,'--head','b'*40,'--token-file',str(self.root/'unused-token')]
        with patch.object(sys,'argv',argv),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(review.main(),1)
        self.assertEqual(self.mode(self.evidence),0o755)
        self.assertEqual(self.mode(self.parent),0o750)

    def test_ca_environment_rejects_replaceable_and_symlinked_ancestors(self):
        ca=Path('/fixture/system/ca.pem');parent=ca.parent
        for uid,mode in [(1000,stat.S_IFDIR|0o755),(0,stat.S_IFDIR|0o775),(0,stat.S_IFLNK|0o777)]:
            def metadata(path):
                if path==ca:return SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o644)
                if path==parent:return SimpleNamespace(st_uid=uid,st_mode=mode)
                return SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o755)
            with self.subTest(uid=uid,mode=mode),patch.object(Path,'lstat',metadata):
                self.assertNotIn('SSL_CERT_FILE',review.reviewer_transport_environment({'SSL_CERT_FILE':str(ca)}))

    def test_ca_environment_accepts_complete_root_owned_chain(self):
        ca=Path('/fixture/system/ca.pem')
        def metadata(path):
            return SimpleNamespace(st_uid=0,st_mode=(stat.S_IFREG|0o644) if path==ca else stat.S_IFDIR|0o755)
        with patch.object(Path,'lstat',metadata):
            self.assertEqual(review.reviewer_transport_environment({'SSL_CERT_FILE':str(ca)}),{'SSL_CERT_FILE':str(ca)})


if __name__=='__main__':unittest.main()
