import shutil
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent
REPO = TOOLS.parent
sys.path.insert(0, str(TOOLS))

IGNORE = shutil.ignore_patterns(".git", "dist", "__pycache__", ".pytest_cache", ".venv", ".local")


@pytest.fixture
def repo(tmp_path):
    """A throwaway copy of the repository that tests can break freely."""
    dst = tmp_path / "repo"
    shutil.copytree(REPO, dst, ignore=IGNORE)
    return dst


@pytest.fixture
def buffet(repo):
    return repo / "categories" / "demo" / "buffet"
