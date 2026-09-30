import json
import re
import tomllib
from pathlib import Path

from tools.publish_check import SERVER_JSON, contains_mcp_name_token

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
# A server name, stopped by whatever the registry accepts as a boundary.
_CLAIM = re.compile(r"mcp-name: ([A-Za-z0-9._/-]+?)(?=-->|--!>|[^A-Za-z0-9._/-]|$)")


def _server():
    return json.loads(SERVER_JSON.read_text())


def _project():
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]


def test_server_json__schema__is_the_2025_12_11_release():
    assert _server()["$schema"] == SCHEMA


def test_server_json__name__is_the_one_and_only_name_the_readme_claims():
    readme = (ROOT / "README.md").read_text()
    assert _CLAIM.findall(readme) == [_server()["name"]]
    assert contains_mcp_name_token(readme, _server()["name"])


def test_server_json__versions__match_pyproject():
    server = _server()
    assert server["version"] == _project()["version"]
    assert [package["version"] for package in server["packages"]] == [_project()["version"]]


def test_server_json__package__is_this_pypi_project_over_stdio():
    (package,) = _server()["packages"]
    assert package["registryType"] == "pypi"
    assert package["identifier"] == _project()["name"]
    assert package["transport"] == {"type": "stdio"}
    # The registry accepts pypi.org only; any other base URL is refused at publish time.
    assert package.get("registryBaseUrl", "https://pypi.org") == "https://pypi.org"


def test_server_json__description__is_pyproject_summary_within_the_registry_limit():
    description = _server()["description"]
    assert description == _project()["description"]
    assert len(description) <= 100


def test_server_json__repository__is_pyproject_source_url():
    assert _server()["repository"] == {"url": _project()["urls"]["Source"], "source": "github"}


def test_server_json__environment_variables__are_optional_and_read_by_the_config():
    config = (ROOT / "stig_mcp" / "ingest" / "config.py").read_text()
    (package,) = _server()["packages"]
    variables = package["environmentVariables"]
    assert variables, "server.json must declare STIG_MCP_DATA"
    for variable in variables:
        assert f'"{variable["name"]}"' in config, variable["name"]
        # A required variable becomes a prompt every gallery install must answer.
        assert variable.get("isRequired", False) is False
