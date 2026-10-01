"""Evidence destination hardening must never chmod unrelated ancestors."""
import os
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


if __name__=='__main__':unittest.main()
