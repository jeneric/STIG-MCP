# stig-mcp

Local MCP server that maps MITRE ATT&CK® techniques (and actors) to the NIST
800-53r5 controls that mitigate them, with the DISA STIG fix and check steps for
the systems under consideration, severity-ordered, and ATT&CK's own mitigations and
detections where ATT&CK publishes them.

<!-- mcp-name: io.github.jeneric/stig-mcp -->

## Prerequisite

stig-mcp is published on [PyPI](https://pypi.org/project/stig-mcp/) and runs through `uvx`,
which comes with [uv](https://docs.astral.sh/uv/).
[Install uv](https://docs.astral.sh/uv/getting-started/installation/), then check that
`uvx --version` runs in a new terminal. Restart VS Code or Claude Code after installing uv
so it sees the new `PATH`.

## Quick start

### VS Code (GitHub Copilot)

1. Click this badge. VS Code opens and offers to install stig-mcp; choose **Install**.

   [![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_stig--mcp-0098FF?logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect/mcp/install?name=stig-mcp&config=%7B%22type%22%3A%22stdio%22%2C%22command%22%3A%22uvx%22%2C%22args%22%3A%5B%22stig-mcp%22%5D%2C%22env%22%3A%7B%22UV_SYSTEM_CERTS%22%3A%22true%22%2C%22UV_NATIVE_TLS%22%3A%22true%22%7D%7D)

2. Open Copilot Chat and set the mode dropdown to **Agent**. MCP tools are not available in
   Ask or Edit mode.
3. Ask: `Install the stig-mcp knowledge base.` This is a one-time download of about 6 MB.
   Allow the tool when VS Code asks.

If that doesn't work, see [troubleshooting](https://github.com/jeneric/STIG-MCP/blob/main/docs/install.md#troubleshooting) or
[setting up VS Code by hand](https://github.com/jeneric/STIG-MCP/blob/main/docs/install.md#vs-code-github-copilot).

### Claude Code

1. Inside a Claude Code session (2.1.275 or later), run:

       /plugin install stig-mcp --marketplace jeneric/STIG-MCP

2. Ask: `Install the stig-mcp knowledge base.` This is a one-time download of about 6 MB.
   Allow the tool when Claude Code asks.

If that doesn't work, see [troubleshooting](https://github.com/jeneric/STIG-MCP/blob/main/docs/install.md#troubleshooting) or
[setting up Claude Code by hand](https://github.com/jeneric/STIG-MCP/blob/main/docs/install.md#claude-code).

## Example prompts

With the knowledge base installed, try:

1. `What DISA STIG steps mitigate T1078 on Windows 11?`
2. `Which ATT&CK techniques does APT29 use?`
3. `Which STIG benchmarks apply to RHEL 9?`
4. `What can I detect of APT29 on Windows Server 2022 with Security and Sysmon logs?`

[More example prompts](https://github.com/jeneric/STIG-MCP/blob/main/docs/user-guide.md#example-prompts) are in the user guide, with
[how to get more out of it](https://github.com/jeneric/STIG-MCP/blob/main/docs/user-guide.md#getting-more-out-of-it) and
[how to make sure the agent answers from the server](https://github.com/jeneric/STIG-MCP/blob/main/docs/user-guide.md#getting-the-llm-to-use-the-server).

## Other MCP clients

Use this only if you are not using VS Code or Claude Code. Any client that launches a local
(stdio) MCP server works with this configuration, shown in the common `mcpServers` shape:

```json
{
  "mcpServers": {
    "stig-mcp": {
      "command": "uvx",
      "args": ["stig-mcp"],
      "env": { "UV_SYSTEM_CERTS": "true", "UV_NATIVE_TLS": "true" }
    }
  }
}
```

The two environment variables let uv download stig-mcp
[behind a TLS-inspecting proxy](https://github.com/jeneric/STIG-MCP/blob/main/docs/install.md#behind-a-tls-inspecting-proxy). They are
harmless on most other hosts; that section names the one exception. Then ask the agent to install the stig-mcp knowledge base, as in the
quick start.

[docs/install.md](https://github.com/jeneric/STIG-MCP/blob/main/docs/install.md) has the details:

- manual [VS Code](https://github.com/jeneric/STIG-MCP/blob/main/docs/install.md#vs-code-github-copilot) and [Claude Code](https://github.com/jeneric/STIG-MCP/blob/main/docs/install.md#claude-code) setup
- [running from a source checkout](https://github.com/jeneric/STIG-MCP/blob/main/docs/install.md#running-from-a-source-checkout)
- [installing the knowledge base](https://github.com/jeneric/STIG-MCP/blob/main/docs/install.md#installing-the-knowledge-base) without an agent or without network access
- [where the data lives](https://github.com/jeneric/STIG-MCP/blob/main/docs/install.md#where-the-data-lives)
- [troubleshooting](https://github.com/jeneric/STIG-MCP/blob/main/docs/install.md#troubleshooting)

## What this server fetches

- The MCP server contacts nothing unless `check_sources` or `install_knowledge_base` is
  called. Then it sends HTTPS GET requests to `api.github.com` (this repository's release
  listing) and `github.com` (`/jeneric/STIG-MCP/releases/download/...`), which redirects to
  `release-assets.githubusercontent.com` or `objects.githubusercontent.com`. Any other URL, a
  redirect included, is refused. Nothing is uploaded, and there is no telemetry.
  `install_knowledge_base` given a file path and its SHA-256 requests nothing at all.
- `stig-mcp-install-kb` contacts the same hosts, and nothing at all with `--file`.
- `stig-mcp-fetch`, used only to build the knowledge base yourself, downloads from
  `raw.githubusercontent.com` and `api.github.com` (MITRE ATT&CK, the CTID mapping, the NIST
  800-53 catalog) and from `dl.dod.cyber.mil` (DISA).

[PRIVACY.md](https://github.com/jeneric/STIG-MCP/blob/main/PRIVACY.md) states what each of these requests sends and what is stored locally.

## Documentation

- [docs/install.md](https://github.com/jeneric/STIG-MCP/blob/main/docs/install.md): installation details for every client, where the data lives, and troubleshooting.
- [docs/user-guide.md](https://github.com/jeneric/STIG-MCP/blob/main/docs/user-guide.md): for a person talking to an LLM that has this server wired in.
- [docs/operations.md](https://github.com/jeneric/STIG-MCP/blob/main/docs/operations.md): for whoever installs, builds and maintains the knowledge base.
- [SECURITY.md](https://github.com/jeneric/STIG-MCP/blob/main/SECURITY.md): reporting a vulnerability, and what is in scope.
- [CONTRIBUTING.md](https://github.com/jeneric/STIG-MCP/blob/main/CONTRIBUTING.md): working from a source checkout, running the tests, and the project's conventions.
- [RELEASING.md](https://github.com/jeneric/STIG-MCP/blob/main/RELEASING.md): for the maintainer, publishing the package to PyPI and the MCP Registry.
- [PRIVACY.md](https://github.com/jeneric/STIG-MCP/blob/main/PRIVACY.md): what the server and the fetch tool contact, and what is stored locally.

## Third-party content

The knowledge base aggregates MITRE ATT&CK, CTID mapping, DISA STIG, DISA CCI
list, and NIST OSCAL content. See [NOTICE](https://github.com/jeneric/STIG-MCP/blob/main/NOTICE) for attribution and licensing obligations
and [licenses/apache-2.0.txt](https://github.com/jeneric/STIG-MCP/blob/main/licenses/apache-2.0.txt) for the Apache 2.0
license text that notice requires.

## Development

Developed with the assistance of Claude Code (Anthropic). All changes were reviewed and
tested by the maintainer.
