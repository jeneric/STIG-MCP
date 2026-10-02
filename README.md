# stig-mcp

Local MCP server that maps MITRE ATT&CK® techniques (and actors) to the NIST
800-53r5 controls that mitigate them, with the DISA STIG fix and check steps for
the systems under consideration, severity-ordered.

<!-- mcp-name: io.github.jeneric/stig-mcp -->

## Install

stig-mcp is on [PyPI](https://pypi.org/project/stig-mcp/). With
[uv](https://docs.astral.sh/uv/), a client runs it with no separate install step:

    uvx stig-mcp

`uvx` comes with uv; [install uv](https://docs.astral.sh/uv/getting-started/installation/)
first if `uvx --version` does not run. The VS Code badge and the Claude Code plugin below both
need it.

From a source checkout instead, install the dependencies with:

    uv sync

The commands below are written for a checkout (`uv run ...`). Without one, run the same entry
point with `uvx --from stig-mcp`, for example `uvx --from stig-mcp stig-mcp-install-kb`.

## Quickstart

1. Wire the server into a client (see "Run the server" below) and start it.
2. Ask the agent to install the knowledge base. It calls the `install_knowledge_base`
   tool, which downloads the newest published release from this project's GitHub releases
   and verifies its SHA-256 before installing it. From a terminal the same is
   `uv run stig-mcp-install-kb`. A host that cannot reach GitHub installs from a file; see
   [docs/operations.md](https://github.com/jeneric/STIG-MCP/blob/main/docs/operations.md), "Install a prebuilt knowledge base".
3. Or build it yourself: `uv run stig-mcp-fetch` downloads ATT&CK, the CTID mapping, the
   800-53 catalog, and DISA's STIG content. **This transfers roughly a gigabyte** and
   refuses to start with less than 2 GiB free. Then `uv run stig-mcp-ingest` builds the
   knowledge base.

On a host that cannot reach `dl.dod.cyber.mil`, place the artifacts in the sources
directory yourself and go straight to `stig-mcp-ingest`. That is a first-class path rather
than a fallback: the ingest reads a directory and never consults the fetch. See
[docs/operations.md](https://github.com/jeneric/STIG-MCP/blob/main/docs/operations.md), "Placing the sources by hand".

Afterwards, `uv run stig-mcp-fetch --check` reports what MITRE ATT&CK, CTID, NIST and DISA
have published since, exiting 10 when there is something to take and 3 when a source could not
be reached, and `--refresh` takes it.
Neither rebuilds the knowledge base; see "Keeping current" in the same document.

## Run the server

    uvx stig-mcp

or, from a checkout, `uv run stig-mcp`.

This is a stdio MCP server: it speaks JSON-RPC on stdin/stdout and logs to stderr,
so it is launched by an MCP client rather than run standalone.

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

### GitHub Copilot in VS Code

[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_stig--mcp-0098FF?logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect/mcp/install?name=stig-mcp&config=%7B%22type%22%3A%22stdio%22%2C%22command%22%3A%22uvx%22%2C%22args%22%3A%5B%22stig-mcp%22%5D%2C%22env%22%3A%7B%22UV_SYSTEM_CERTS%22%3A%22true%22%2C%22UV_NATIVE_TLS%22%3A%22true%22%7D%7D)

Or run **MCP: Open User Configuration** from the Command Palette and add:

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

From a checkout, create `.vscode/mcp.json` in this repository instead (git-ignored, so it
stays local):

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

Then:

1. Open Copilot Chat and set the mode dropdown to **Agent**. MCP tools are not
   available in Ask or Edit mode.
2. Command Palette (`Ctrl+Shift+P`, or `Cmd+Shift+P` on macOS) and run
   **MCP: List Servers**, select `stig-mcp`, then **Start**. Trust the server when
   prompted, since it runs a local command.
3. Click **Configure Tools** in the chat input to confirm the eight tools are listed
   and enabled.
4. Reference a tool explicitly to verify the wiring, rather than hoping the model
   picks it up on its own. See [docs/user-guide.md](https://github.com/jeneric/STIG-MCP/blob/main/docs/user-guide.md)'s "Getting the
   LLM to use the server" for a prompt shape that reliably does this.

Copilot saves a tool answer over 8 KB to a temporary file and reads it back, so with
manual permissions it asks to read a file named like `…copilot-tool-output-….txt`
outside the workspace. That file is this server's answer; allow it.

To debug, run **MCP: List Servers**, select the server, and choose **Show Output**.
The two common failures are that `uvx` or `uv` is not on the `PATH` VS Code inherited,
which looks like a broken server but is a missing command, and an absent knowledge base.
For the first, use the absolute path (`which uvx` or `which uv`) as `command`. A missing
`uvx` shows in VS Code's output as `Connection state: Error spawn uvx ENOENT`, and in
`claude mcp list` as `Failed to connect — ENOENT: Executable not found in $PATH: "uvx"`. For
the second, see [docs/operations.md](https://github.com/jeneric/STIG-MCP/blob/main/docs/operations.md).

### Other clients

Any MCP client that launches a stdio server works, with `uvx stig-mcp` as the command. For
Claude Code, install the plugin from this repository's marketplace, inside a session (Claude
Code 2.1.275 or later):

    /plugin install stig-mcp --marketplace jeneric/STIG-MCP

or from a shell, `claude plugin marketplace add jeneric/STIG-MCP` then
`claude plugin install stig-mcp@stig-mcp`. The plugin pins the current release, and
`claude plugin update stig-mcp@stig-mcp` moves it to the next one. Without the plugin:

    claude mcp add stig-mcp -e UV_SYSTEM_CERTS=true -e UV_NATIVE_TLS=true -- uvx stig-mcp

From a checkout, `uv run` locates the project from the working directory, so a client that
starts elsewhere needs `--directory`, which makes the command independent of where it is
launched:

    uv run --directory /path/to/STIG-MCP stig-mcp

or, from the repository root, `claude mcp add stig-mcp -- uv run stig-mcp`.

By default the knowledge base is not found relative to the working directory, so only
`uv run` cares where the client starts the server. Where it *is* found depends on whether this is a
checkout or an installed copy. (A relative `STIG_MCP_DATA` does resolve against the working
directory, so give it an absolute path if the client's is not yours.)

### Behind a TLS-inspecting proxy

Corporate networks that inspect TLS re-sign traffic with their own CA, which IT installs in the
operating system's certificate store. stig-mcp verifies its own downloads against that store,
and also trusts a CA file named by `SSL_CERT_FILE`; `SSL_CERT_DIR` is honored only on Linux.
uvx, which fetches stig-mcp itself, trusts only its bundled roots unless told otherwise, so
the client configurations above (the VS Code badge and `mcp.json`, the Claude Code plugin, and
`claude mcp add`) set two environment variables: `UV_SYSTEM_CERTS` for uv 0.11 and later, and
`UV_NATIVE_TLS` for older uv, which ignores the newer name. On newer uv the second one prints a
deprecation warning, which is harmless. The bare `uvx stig-mcp` commands and the checkout
configurations set neither.

If you run `uvx` by hand on such a network, tell uv first. With uv 0.11 or later, set
`UV_SYSTEM_CERTS=true` in its environment or add `system-certs = true` to your `uv.toml`.
With older uv, set `UV_NATIVE_TLS=true` or add `native-tls = true` instead: older uv rejects
a `uv.toml` holding `system-certs`, and then every uv command fails.

On a host whose operating system certificate store is empty (for example a minimal Linux
container without `ca-certificates`), drop the two variables, because uv then has no roots at
all.

### Where the data lives

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

## Example prompts

With the knowledge base installed and the server wired into an agent, these are answered
from it:

1. `What DISA STIG steps mitigate T1078 on Windows 11?`
2. `Which ATT&CK techniques does APT29 use?`
3. `Which STIG benchmarks apply to RHEL 9?`

## Documentation

- [docs/operations.md](https://github.com/jeneric/STIG-MCP/blob/main/docs/operations.md): for whoever installs, builds and maintains the knowledge base.
- [docs/user-guide.md](https://github.com/jeneric/STIG-MCP/blob/main/docs/user-guide.md): for a person talking to an LLM that has this server wired in.
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
