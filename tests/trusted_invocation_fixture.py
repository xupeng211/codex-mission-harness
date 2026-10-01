"""Disposable canonical metadata; only the fixture executable's UID is simulated."""
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch


@contextmanager
def canonical_fixture():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        binary = root / 'codex'; binary.write_text('# offline fixture; never executed\n'); binary.chmod(0o755)
        home = root / 'home'; home.mkdir(mode=0o700)
        auth = home / 'auth.json'; auth.write_text('{}'); auth.chmod(0o600)
        original = Path.stat
        def metadata(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path == binary:
                fields = list(info); fields[4] = 0
                return os.stat_result(fields)
            return info
        with patch.object(Path, 'stat', metadata):
            yield binary, home
