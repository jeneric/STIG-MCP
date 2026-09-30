# Security Policy

## Supported versions

stig-mcp is pre-1.0. Security fixes land on `main` and ship in the next release; only the
latest release is supported.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
[Security > Report a vulnerability](https://github.com/jeneric/STIG-MCP/security/advisories/new).
Do not open a public issue, discussion, or pull request for a suspected vulnerability.

Include what you can of:

- the affected command or tool (`stig-mcp`, `stig-mcp-fetch`, `stig-mcp-ingest`,
  `stig-mcp-extract`, `stig-mcp-install-kb`) and the version or commit;
- the input that triggers it, such as a crafted archive, index page, release asset, or tool
  argument;
- what happens, and what you expected instead.

This is a single-maintainer project, so responses are best effort. You will get an
acknowledgment once the report is read, and credit in the advisory unless you ask otherwise.

## Scope

In scope is the code in this repository, including:

- the MCP server, which runs locally over stdio and reads a local SQLite knowledge base;
  two of its tools contact the network, `check_sources` and `install_knowledge_base`, and
  only this project's GitHub releases (github.com/jeneric/STIG-MCP), reached through
  api.github.com, github.com and GitHub's release-asset hosts
  (release-assets.githubusercontent.com, objects.githubusercontent.com);
- the knowledge-base install path shared by `install_knowledge_base` and
  `stig-mcp-install-kb`: the release listing, the release assets (`SHA256SUMS`,
  `release.json` and the `.sqlite.xz`), their verification and decompression, and the
  replacement of the installed file, including an install from a local file;
- `stig-mcp-fetch`, which downloads from MITRE's, CTID's and NIST's GitHub repositories and
  from DISA;
- `stig-mcp-extract` and `stig-mcp-ingest`, which unpack and parse those downloads;
- the knowledge-base release pipeline, `.github/workflows/kb-release.yml` and
  `tools/kb_package.py`, `tools/kb_verify.py` and `tools/kb_release.py` (repository only, not in
  the package), which build, verify and draft the releases that `install_knowledge_base` installs;
- the integrity model of those releases: a release is verified by SHA-256 only. `SHA256SUMS`
  and `release.json` must agree, and the download and the decompressed file must both match
  them, all before anything is replaced. There is no signature or attestation. A release
  reaches users only after the maintainer publishes its draft. The workflow never publishes a
  release: it creates drafts, replaces unpublished ones, and records the tag on the
  `kb-latest` branch.
- the package publishing pipeline, `.github/workflows/publish.yml` and
  `tools/publish_check.py` (repository only, not in the package): a manual run uploads a
  development build to TestPyPI and checks what TestPyPI serves; a `v*` tag publishes to PyPI
  by trusted publishing and then `server.json` to the MCP Registry.

Report the same way if you find Controlled Unclassified Information (CUI) or other
content that should not be public in this repository or in any knowledge base built with it.

Out of scope: errors in the upstream content itself (ATT&CK, the CTID mapping, NIST SP
800-53, DISA STIGs). Report those to their publishers.
