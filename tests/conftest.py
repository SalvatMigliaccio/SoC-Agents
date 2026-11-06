"""Shared test configuration.

The `test_environment` fixture (autouse=True, so it is active in EVERY test) makes
the core read the fictitious logs in tests/tests_data/ instead of dates/, and sends
reports and blocklist to a temporary folder that pytest deletes on its own.
"""
from pathlib import Path

import pytest

from soc import config

TEST_DATA_DIR = Path(__file__).resolve().parent / "tests_data"


@pytest.fixture(autouse=True)
def test_environment(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DATA_DIR", TEST_DATA_DIR)
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(config, "BLOCKLIST_FILE", tmp_path / "blocklist.txt")
    return tmp_path