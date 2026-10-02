# Privacy

stig-mcp collects no data about you and has no telemetry. It runs on your machine and reads a
local knowledge base.

## The MCP server

- The server makes no network request unless an agent calls `check_sources` or
  `install_knowledge_base`, or you run `stig-mcp-install-kb` without `--file`.
- Those requests are HTTPS GETs to `api.github.com`, `github.com` and GitHub's release-asset
  hosts `release-assets.githubusercontent.com` and `objects.githubusercontent.com`, for this
  project's releases only. They carry no request body and a fixed `User-Agent` of `stig-mcp`.
- GitHub sees the requesting IP address and handles it under its own privacy statement:
  https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement
- Certificate verification, for these requests and the fetch below, uses the operating system,
  which may itself fetch certificate data (for example revocation status or missing
  intermediates) from the certificate authorities' servers; stig-mcp's own requests are
  unchanged.
- One value an agent supplies does reach GitHub: the `release` argument of
  `install_knowledge_base` becomes part of the request URL to `api.github.com`, and it must
  have the form `kb-YYYY-MM-DD`.
- `install_knowledge_base` given a local file path and its SHA-256 makes no request at all.
- Your prompts, the rest of what an agent asks the tools, and the answers are never sent
  anywhere by stig-mcp. Whatever client runs the agent has its own policy.

## Building the knowledge base yourself

- `stig-mcp-fetch` downloads from `raw.githubusercontent.com` and `api.github.com` (MITRE
  ATT&CK, the CTID mapping, the NIST catalog) and from `dl.dod.cyber.mil` (DISA). It sends the
  same `User-Agent` of `stig-mcp`.
- The fetch follows HTTP redirects with urllib's default handling and has no host allowlist,
  unlike the server's release requests, so a redirect can send it to a host not listed here.
- Those hosts see your IP address under their own policies. Nothing is sent but the requests.

## What is stored locally

- The knowledge base, the downloaded sources, the fetch manifest and the installed-release
  record, in the data directory [docs/install.md](docs/install.md#where-the-data-lives)
  describes. Nothing leaves the machine.
