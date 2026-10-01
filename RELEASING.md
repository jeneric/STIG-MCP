# Releasing

For the maintainer. Building and publishing a knowledge base is covered in
[docs/operations.md](docs/operations.md), "How knowledge-base releases are built"; this
file covers publishing the package.

## Publishing the package

`.github/workflows/publish.yml` publishes `stig-mcp` to PyPI and its `server.json` to the
MCP Registry. It has two triggers:

- **Started by hand, it is a dry run.** It builds a development version,
  `<version>.dev<N>`, uploads it to TestPyPI, and then checks that TestPyPI serves exactly
  those files and that their description carries the registry's `mcp-name` line. It also
  validates `server.json` with `mcp-publisher validate`. Nothing reaches PyPI or the
  registry.
- **A `v*` tag is a release.** The tag must name the version in `pyproject.toml`. The
  workflow uploads to PyPI, waits until PyPI serves the files, and publishes `server.json`
  to the MCP Registry. Versions are permanent on both, so a fix to metadata alone needs a
  new version.

Both uploads use trusted publishing, so no token is stored. Each index must first be told
to trust this workflow. On TestPyPI and on PyPI, add a pending publisher with these
values:

| Field | Value |
|---|---|
| PyPI project name | `stig-mcp` |
| Owner | `jeneric` |
| Repository name | `STIG-MCP` |
| Workflow name | `publish.yml` |
| Environment name | `testpypi` (on TestPyPI) or `pypi` (on PyPI) |

Some versions of the form ask for a single repository URL instead of owner and repository
name; enter `https://github.com/jeneric/STIG-MCP` there.

Each GitHub environment should accept only the refs that may publish from it: `testpypi`
the `main` branch, and `pypi` tags matching `v*` (Settings, Environments, "Deployment
branches and tags"). Also make `pypi` require a reviewer, so every release waits for an
approval.

Then start a dry run with `gh workflow run publish.yml` and follow it with
`gh run watch`. If a run fails after its upload, re-run only the failed jobs: re-running
all of them builds a new version.

A release also bumps the Claude Code plugin: `version` in
`plugins/stig-mcp/.claude-plugin/plugin.json` and the `stig-mcp==` pin in
`plugins/stig-mcp/.mcp.json` both name the new version. `tests/test_plugin.py` fails until they
match `pyproject.toml`, so CI on `main` catches a missed bump before the tag.
