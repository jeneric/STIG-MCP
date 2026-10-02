# Installing stig-mcp

The README's quick start covers the usual path: install uv, click the VS Code badge or install
the Claude Code plugin, then ask the agent to install the knowledge base. This document has
the details behind it and the fixes for when it does not work.

## VS Code (GitHub Copilot)

### Configuring by hand

Instead of the badge, run **MCP: Open User Configuration** from the Command Palette and add:

```json
{
  "servers": {
    "stig-mcp": {
      "type": "stdio",
      "command": "uvx",
      "args": ["stig-mcp"],
      "env": { "UV_SYSTEM_CERTS": "true", "UV_NATIVE_TLS": "true" }
    }
  }
}
```

### Starting the server and checking the tools

1. Open Copilot Chat and set the mode dropdown to **Agent**. MCP tools are not
   available in Ask or Edit mode.
2. Command Palette (`Ctrl+Shift+P`, or `Cmd+Shift+P` on macOS) and run
   **MCP: List Servers**, select `stig-mcp`, then **Start**. Trust the server when
   prompted, since it runs a local command.
3. Click **Configure Tools** in the chat input to confirm the eight tools are listed
   and enabled.
4. Reference a tool explicitly to verify the wiring, rather than hoping the model
   picks it up on its own. See [user-guide.md](user-guide.md)'s "Getting the
   LLM to use the server" for a prompt shape that reliably does this.

Copilot saves a tool answer over 8 KB to a temporary file and reads it back, so with
manual permissions it asks to read a file named like `…copilot-tool-output-….txt`
outside the workspace. That file is this server's answer; allow it.

To see the server's log, run **MCP: List Servers**, select the server, and choose
**Show Output**. Not working? See [Troubleshooting](#troubleshooting).

## Claude Code

The quick start installs the plugin inside a session. From a shell instead:

    claude plugin marketplace add jeneric/STIG-MCP
    claude plugin install stig-mcp@stig-mcp

The plugin pins the current release, and `claude plugin update stig-mcp@stig-mcp` moves it to
the next one. Without the plugin:

    claude mcp add stig-mcp -e UV_SYSTEM_CERTS=true -e UV_NATIVE_TLS=true -- uvx stig-mcp

Not working? See [Troubleshooting](#troubleshooting).

## Running from a source checkout

Install the dependencies with:

    uv sync

The commands in this project's documents are written for a checkout (`uv run ...`). Without
one, run the same entry point with `uvx --from stig-mcp`, for example
`uvx --from stig-mcp stig-mcp-install-kb`.

For VS Code, create `.vscode/mcp.json` in the checkout (git-ignored, so it stays local):

```json
{
  "servers": {
    "stig-mcp": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "stig-mcp"],
      "cwd": "${workspaceFolder}"
    }
  }
}
```

`uv run` locates the project from the working directory, so a client that starts elsewhere
needs `--directory`, which makes the command independent of where it is launched:

    uv run --directory /path/to/STIG-MCP stig-mcp

or, from the repository root, `claude mcp add stig-mcp -- uv run stig-mcp`.

By default the knowledge base is not found relative to the working directory, so only
`uv run` cares where the client starts the server. Where it *is* found depends on whether this
is a checkout or an installed copy; see [Where the data lives](#where-the-data-lives). (A
relative `STIG_MCP_DATA` does resolve against the working directory, so give it an absolute
path if the client's is not yours.)

## How the server runs

`uvx stig-mcp` (or `uv run stig-mcp` from a checkout) starts a stdio MCP server: it speaks
JSON-RPC on stdin/stdout and logs to stderr, so it is launched by an MCP client rather than
run standalone.

It starts whether or not the knowledge base exists, and it never answers from one it
cannot trust. Called before the knowledge base is installed, or against one an older release
wrote, every tool returns a `not_ready` payload instead of an answer: the reason, which
source files it can and cannot see, the sources directory it looked in, and the next steps,
led by the `install_knowledge_base` tool and followed by the commands to run. Each command
comes in two forms: `run`, which works from the server's own environment, and `as_installed`,
which a person can type into a terminal, written for how the server was installed (`uvx`, a
checkout, or an installed copy). That is deliberate, so an agent can read the remedy from
the tool result rather than the operator having to find a log pane. Install or rebuild the
knowledge base and the running server picks it up without a restart.

The `check_sources` tool tells an agent whether a newer knowledge base is published. It and
`install_knowledge_base` are the only two tools that contact the network, and they reach
only this project's GitHub releases.

## Installing the knowledge base

- **Through the agent:** ask it to install the stig-mcp knowledge base. It calls the
  `install_knowledge_base` tool, which downloads the newest published release from this
  project's GitHub releases and verifies its SHA-256 before installing it.
- **From a terminal:** `uvx --from stig-mcp stig-mcp-install-kb`, or
  `uv run stig-mcp-install-kb` from a checkout, does the same.
- **Without access to GitHub:** install from a file; see [operations.md](operations.md),
  "Install a prebuilt knowledge base".
- **Building it yourself:** `uv run stig-mcp-fetch` downloads ATT&CK, the CTID mapping, the
  800-53 catalog, and DISA's STIG content. **This transfers roughly a gigabyte** and refuses
  to start with less than 2 GiB free. Then `uv run stig-mcp-ingest` builds the knowledge base.

On a host that cannot reach `dl.dod.cyber.mil`, place the artifacts in the sources
directory yourself and go straight to `stig-mcp-ingest`. That is a first-class path rather
than a fallback: the ingest reads a directory and never consults the fetch. See
[operations.md](operations.md), "Placing the sources by hand".

Afterwards, `uv run stig-mcp-fetch --check` reports what MITRE ATT&CK, CTID, NIST and DISA
have published since, exiting 10 when there is something to take and 3 when a source could not
be reached, and `--refresh` takes it.
Neither rebuilds the knowledge base; see "Keeping current" in [operations.md](operations.md).

## Where the data lives

Two environment variables override the defaults, and the defaults differ between a source
checkout and an installed copy (which includes `uvx stig-mcp`):

| | source checkout | installed, POSIX and macOS | installed, Windows |
|---|---|---|---|
| data directory (`STIG_MCP_DATA`) | `stig_mcp/data/` | `$XDG_DATA_HOME/stig-mcp`, else `~/.local/share/stig-mcp` | `$XDG_DATA_HOME/stig-mcp`, else `%LOCALAPPDATA%\stig-mcp`, else `~\.local\share\stig-mcp` |
| mapping overrides (`STIG_MCP_OVERRIDES`) | `overrides.yaml` at the repository root | `$XDG_CONFIG_HOME/stig-mcp/overrides.yaml`, else `~/.config/stig-mcp/overrides.yaml` | `$XDG_CONFIG_HOME/stig-mcp/overrides.yaml`, else `%LOCALAPPDATA%\stig-mcp\overrides.yaml`, else `~\.config\stig-mcp\overrides.yaml` |

A checkout is a directory holding both the package and the `pyproject.toml` that declares
it, so an editable install counts as one. XDG is used on POSIX, including macOS. On Windows
with the XDG variables unset, the default is `%LOCALAPPDATA%`, because a roaming profile
copies `~/.local/share` at every logon and logoff, and this project's downloads can run to a
gigabyte; when
`%LOCALAPPDATA%` is set this puts the mapping overrides file inside the data directory rather
than beside it, since Windows has one such variable rather than XDG's separate data and config
locations. (With `%LOCALAPPDATA%` unset, Windows falls back to the same separate `~/.config`
and `~/.local/share` trees POSIX uses, so the two stay apart in that case, same as the table
above shows.)

**The XDG variables are read first on every platform, Windows included**, as the table's
Windows column shows: a Windows host with `XDG_DATA_HOME` set uses it and never reaches
`%LOCALAPPDATA%`, so the roaming argument above holds only where that variable is unset. The
order is kept so that an existing install's data directory never moves under it.
`STIG_MCP_DATA` and `STIG_MCP_OVERRIDES` outrank everything above and are the escape hatch
everywhere, for a native location or any other.

`stig-mcp-ingest` creates the data directory if it does not exist. It refuses to run when
`STIG_MCP_OVERRIDES` names a file that is not there, rather than silently applying no
overrides; a missing file at the default location is fine, because that file is optional.

## Troubleshooting

### The server does not start: `uvx` not found

The client could not find `uvx` (or `uv`) on the `PATH` it inherited, which looks like a
broken server but is a missing command. In VS Code's output it shows as
`Connection state: Error spawn uvx ENOENT`, and in `claude mcp list` as
`Failed to connect — ENOENT: Executable not found in $PATH: "uvx"`. Restart the client after
installing uv, or use the absolute path as `command`: `which uvx` (or `which uv` for a checkout
configuration), and `where` instead of `which` on Windows.

### Every tool answers `not_ready`

The knowledge base is not installed yet, or an older release wrote it. Ask the agent to
install it; the `not_ready` payload names the exact next steps. See
[How the server runs](#how-the-server-runs).

### Behind a TLS-inspecting proxy

Corporate networks that inspect TLS re-sign traffic with their own CA, which IT installs in the
operating system's certificate store. stig-mcp verifies its own downloads against that store,
and also trusts a CA file named by `SSL_CERT_FILE`; `SSL_CERT_DIR` is honored only on Linux.
uvx, which fetches stig-mcp itself, trusts only its bundled roots unless told otherwise, so
the configurations this project ships (the VS Code badge, the Claude Code plugin, the README's
"Other MCP clients", and the `mcp.json` and `claude mcp add` examples in this document) set two
environment variables: `UV_SYSTEM_CERTS` for uv 0.11 and later, and `UV_NATIVE_TLS` for older
uv, which ignores the newer name. On newer uv the second one prints a deprecation warning,
which is harmless. A bare `uvx stig-mcp` and the checkout configurations set neither.

If you run `uvx` by hand on such a network, tell uv first. With uv 0.11 or later, set
`UV_SYSTEM_CERTS=true` in its environment or add `system-certs = true` to your `uv.toml`.
With older uv, set `UV_NATIVE_TLS=true` or add `native-tls = true` instead: older uv rejects
a `uv.toml` holding `system-certs`, and then every uv command fails.

On a host whose operating system certificate store is empty (for example a minimal Linux
container without `ca-certificates`), drop the two variables, because uv then has no roots at
all.

### Downloads time out behind a proxy

Some inspecting proxies hold a whole file to scan it before passing any of it on, so a download
can stall long enough to time out. Two downloads have separate limits:

- **uv fetching stig-mcp and its dependencies** waits 30 seconds for data by default and fails
  with `error decoding response body` or `operation timed out`. Raise the limit with
  `UV_HTTP_TIMEOUT`, in seconds: add `"UV_HTTP_TIMEOUT": "300"` to the `env` of the server's
  configuration, or set it in the terminal before running `uvx` by hand.
- **stig-mcp downloading the knowledge base** also waits 30 seconds, and `UV_HTTP_TIMEOUT`
  does not change that. If it times out, download the release files another way and install
  from a file; see [operations.md](operations.md), "Install a prebuilt knowledge base".

### "This Model Context Protocol server is not in the list of servers allowed by your organization"

This comes from your GitHub Copilot Business or Enterprise policy, not from stig-mcp: the
enterprise or organization restricts which MCP servers run, and its allowlist does not include
this one. **Developer: Policy Diagnostics** in VS Code shows the policy and where it comes from;
`chat.mcp.allowedServers` from "server" means it came from your GitHub account's policy rather
than from the machine.

Only an administrator can change it, by adding an entry under `allowedMcpServers` in the
enterprise's `copilot/managed-settings.json` (most enterprises keep it in a `.github-private`
repository). A `serverCommand` entry must give the exact command and every argument, for example
`{"serverCommand": ["uvx", "stig-mcp"]}` for the badge's configuration. A
`{"serverName": "stig-mcp"}` entry is simpler but weaker, because anyone can give a server that
name.

### The GitHub source archive stops downloading partway

An inspecting proxy may cut off the repository's source zip (`.../archive/...zip`) or a clone,
for example because the test suite holds deliberately hostile inputs for its security tests.
Install from PyPI (`uvx stig-mcp`, as the README's quick start does) instead: the published
package contains no tests.
