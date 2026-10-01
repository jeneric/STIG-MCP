# stig-mcp plugin

Adds the [stig-mcp](https://github.com/jeneric/STIG-MCP) MCP server to Claude Code. It maps
MITRE ATT&CK® techniques and actors to NIST 800-53r5 controls and the DISA STIG check and fix
steps for the systems you name.

Requires [uv](https://docs.astral.sh/uv/getting-started/installation/): the server runs as
`uvx stig-mcp==<version>`.

On first use, ask Claude to install the knowledge base. The server downloads it from this
project's [GitHub releases](https://github.com/jeneric/STIG-MCP/releases) and verifies its
SHA-256; [PRIVACY.md](https://github.com/jeneric/STIG-MCP/blob/main/PRIVACY.md) lists every
request it makes. See the [README](https://github.com/jeneric/STIG-MCP#readme) for everything
else.
