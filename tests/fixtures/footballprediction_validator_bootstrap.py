"""OFFLINE worker boundary: original validators, fake binary/auth only.

The production worker is a new process, so parent test monkeypatches do not
cross that boundary. Called only by the explicit launcher fixture.
"""
from pathlib import Path
import subprocess


def configure(snapshot, driver, binary):
    from harness.adapters import FootballPredictionAdapter
    FootballPredictionAdapter._trusted_base_checkout = lambda *args, **kwargs: Path(snapshot)
    FootballPredictionAdapter.review_environment = lambda *args, **kwargs: FootballPredictionAdapter._trusted_git_environment()
    original = subprocess.Popen
    def launch(argv, *args, **kwargs):
        argv = list(argv)
        wrapper = str(Path(snapshot) / "scripts/devops/codex_independent_review.py")
        if wrapper in argv:
            index = argv.index(wrapper)
            argv[index:index + 1] = [driver, snapshot, "codex", binary]
        return original(argv, *args, **kwargs)
    subprocess.Popen = launch
