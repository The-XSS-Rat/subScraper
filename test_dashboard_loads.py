#!/usr/bin/env python3
"""
The dashboard is one large inline <script>. A load-time runtime error there
blanks the entire UI while every Python test still passes, so this executes the
script against a DOM stub and fails if it throws.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(__file__))

with patch('main.ensure_dirs'), \
     patch('main.init_database'), \
     patch('main.migrate_json_to_sqlite'):
    import main  # noqa: E402

SMOKE_SCRIPT = Path(__file__).parent / "tools" / "dashboard_smoke.js"


def extract_dashboard_script() -> str:
    blocks = re.findall(r"<script>(.*?)</script>", main.INDEX_HTML, re.DOTALL)
    assert blocks, "no inline script found in INDEX_HTML"
    return "\n".join(blocks)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_dashboard_script_loads_without_runtime_errors():
    """
    Catches the class of bug that only shows up in a browser: using a const
    before its declaration, calling an undefined function at load time, and
    similar. `node --check` parses but never executes, so it misses these.
    """
    assert SMOKE_SCRIPT.exists(), f"missing smoke harness at {SMOKE_SCRIPT}"
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
        handle.write(extract_dashboard_script())
        script_path = handle.name
    try:
        result = subprocess.run(["node", str(SMOKE_SCRIPT), script_path],
                                capture_output=True, text=True, timeout=120)
    finally:
        os.unlink(script_path)
    assert result.returncode == 0, (
        "dashboard script failed to load:\n"
        + (result.stderr or result.stdout).strip()
    )


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_dashboard_script_parses():
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
        handle.write(extract_dashboard_script())
        script_path = handle.name
    try:
        result = subprocess.run(["node", "--check", script_path],
                                capture_output=True, text=True, timeout=120)
    finally:
        os.unlink(script_path)
    assert result.returncode == 0, result.stderr


def test_every_referenced_view_has_a_section():
    """Each nav link must point at a section that exists."""
    views = set(re.findall(r'class="nav-link" data-view="([a-z-]+)"', main.INDEX_HTML))
    sections = set(re.findall(r'<section class="module" data-view="([a-z-]+)"', main.INDEX_HTML))
    assert views, "no nav links found"
    assert views <= sections, f"nav links without a section: {sorted(views - sections)}"
