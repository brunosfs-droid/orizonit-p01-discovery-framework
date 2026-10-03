"""Read a historical LAB source pin without downloading files during tests."""
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def guide_revision(path):
    text = (ROOT / path).read_text()
    return re.search(r'(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])', text)[0]


def source_bytes(revision, path):
    return subprocess.run(['git', 'show', revision + ':' + path], cwd=ROOT,
                          check=True, capture_output=True, timeout=15).stdout
