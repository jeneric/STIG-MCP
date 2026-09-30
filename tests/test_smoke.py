import importlib


def test_import_package__stig_mcp__succeeds():
    assert importlib.import_module("stig_mcp") is not None
