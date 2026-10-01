import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARKETPLACE = ROOT / ".claude-plugin" / "marketplace.json"


def _version():
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def _entry():
    (entry,) = json.loads(MARKETPLACE.read_text())["plugins"]
    return entry


def _plugin_dir():
    return ROOT / _entry()["source"]


def _manifest():
    return json.loads((_plugin_dir() / ".claude-plugin" / "plugin.json").read_text())


def test_plugin__version__matches_pyproject():
    assert _manifest()["version"] == _version()


def test_plugin__mcp_server__runs_the_pyproject_version_through_uvx():
    servers = json.loads((_plugin_dir() / ".mcp.json").read_text())["mcpServers"]
    assert servers == {"stig-mcp": {"command": "uvx", "args": [f"stig-mcp=={_version()}"]}}


def test_marketplace__entry__names_the_plugin_its_source_holds():
    # Claude Code installs by the entry name and namespaces by the manifest name; a mismatch
    # makes `claude plugin install stig-mcp@stig-mcp` report the plugin as not found.
    assert _entry()["source"] == "./plugins/stig-mcp"
    assert _entry()["name"] == _manifest()["name"] == "stig-mcp"


def test_plugin_readme__links__are_absolute():
    # The plugin is copied into Claude Code's cache, where a link relative to this repository
    # points nowhere.
    links = re.findall(r"\]\(([^)\s]+)\)", (_plugin_dir() / "README.md").read_text())
    assert links, "the link pattern matched nothing, so no link was checked"
    assert [link for link in links if "://" not in link] == []
