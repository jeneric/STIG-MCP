"""Facts the documentation states that the code decides. Each test extracts the value from the
document and compares it with the code, so the two cannot drift apart unnoticed."""

import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from stig_mcp.kb import freshness, releases
from stig_mcp.server import app as app_module
from stig_mcp.server import tools
from tests.kb.fake_github import FakeGitHub

ROOT = Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs" / "user-guide.md"


def _section(text, heading):
    """The body of one markdown section, up to the next heading of the same or a higher level."""
    start = re.search(rf"^(#+) {re.escape(heading)}[ \t]*$", text, re.M)
    assert start, f"no section headed {heading!r}"
    level = len(start.group(1))
    end = re.compile(rf"^#{{1,{level}}} ", re.M).search(text, start.end())
    return text[start.end() : end.start() if end else len(text)]


def test_section__a_nested_heading__stays_inside_and_a_sibling_ends_it():
    text = "## A\none\n### A1\ntwo\n## B\nthree\n"
    assert _section(text, "A") == "\none\n### A1\ntwo\n"
    assert _section(text, "B") == "\nthree\n"


def test_user_guide__check_sources_keys__match_a_real_result(kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    result = tools.check_sources(app_module.KnowledgeBase(kb_path), opener=github)
    listed = re.search(r"`check_sources\(\)` returns `\{([^}]*)\}`", GUIDE.read_text())
    assert listed, "the tool list must spell check_sources' keys as `{a, b, ...}`"
    assert {key.strip() for key in listed.group(1).split(",")} == set(result)


def test_user_guide__check_sources_actions__match_freshness_actions():
    body = _section(GUIDE.read_text(), "Checking for a newer knowledge base")
    documented = re.findall(r'^- `"([a-z_]+)"`', body, re.M)
    assert documented, 'the actions must be listed as bullets starting - `"name"`'
    assert tuple(documented) == freshness.ACTIONS


def test_user_guide__quoted_text_bound__matches_the_release_quote_limit():
    match = re.search(r"Text quoted from GitHub in a message is cut to (\d+) characters", GUIDE.read_text())
    assert match and int(match.group(1)) == releases._QUOTE_LIMIT


def test_freshness_report__actions_it_returns__are_in_actions(tmp_path, monkeypatch, kb_path):
    # No knowledge base installed: a published release gives "install", none gives
    # "build_locally", so two distinct real actions are checked against the constant.
    from stig_mcp.ingest import config  # noqa: PLC0415

    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    absent = app_module.KnowledgeBase(tmp_path / "absent.sqlite")
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    seen = {
        tools.check_sources(absent, opener=github)["action"],
        tools.check_sources(absent, opener=FakeGitHub())["action"],
    }
    assert seen == {"install", "build_locally"}
    assert seen <= set(freshness.ACTIONS)


README = ROOT / "README.md"
INSTALL = ROOT / "docs" / "install.md"
_URL_HOST = re.compile(r"https?://([a-z0-9.-]+\.[a-z]{2,})")
_BACKTICKED_HOST = re.compile(r"`([a-z0-9.-]+\.[a-z]{2,})`")


def _hosts(package_dir):
    """Every host an http(s) URL literal in the package names, so a new endpoint cannot ship
    undisclosed."""
    found = set()
    for path in Path(package_dir).rglob("*.py"):
        found |= set(_URL_HOST.findall(path.read_text()))
    return found


def _listed_hosts(body):
    """The hostnames a document section lists, each written as a code span."""
    return set(_BACKTICKED_HOST.findall(body))


def test_hosts__the_package__names_the_endpoints_we_know():
    # Positive control: if the scan found nothing, every disclosure test below would pass vacuously.
    assert {"api.github.com", "github.com", "raw.githubusercontent.com", "dl.dod.cyber.mil"} <= _hosts(
        ROOT / "stig_mcp"
    )


def test_readme__fetch_list__lists_exactly_the_hosts_the_package_contacts():
    listed = _listed_hosts(_section(README.read_text(), "What this server fetches"))
    assert listed, "the fetch list must write each host as a code span"
    assert listed == _hosts(ROOT / "stig_mcp") | set(releases.ASSET_REDIRECT_HOSTS)


def test_readme__example_prompts__are_exactly_four():
    body = _section(README.read_text(), "Example prompts")
    assert len(re.findall(r"^\d+\. ", body, re.M)) == 4


def test_docs__relative_links__resolve():
    broken = []
    found = 0
    for doc in [
        README,
        ROOT / "SECURITY.md",
        *(ROOT / "docs").glob("*.md"),
        *ROOT.glob("PRIVACY.md"),
        RELEASING,
        ROOT / "CONTRIBUTING.md",
    ]:
        for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", doc.read_text()):
            found += 1
            if "://" not in target and not (doc.parent / target).exists():
                broken.append(f"{doc.name} -> {target}")
    assert found, "the link pattern matched nothing, so no link was checked"
    assert broken == []


OPERATIONS = ROOT / "docs" / "operations.md"
_INSTALL_HEADING = "Install a prebuilt knowledge base"


def test_operations__fetch_retry__matches_the_constants():
    from stig_mcp.ingest import fetch  # noqa: PLC0415

    match = re.search(
        r"tries each download and the index read up to (\d+) times, waiting (\d+), (\d+) and (\d+) seconds",
        OPERATIONS.read_text(),
    )
    assert match, "the retry sentence must keep its extractable form"
    assert int(match.group(1)) == fetch.RETRY_ATTEMPTS
    assert tuple(int(match.group(n)) for n in (2, 3, 4)) == fetch.RETRY_BACKOFF


def test_operations__retried_http_codes__match_the_transient_codes():
    from stig_mcp.ingest import fetch  # noqa: PLC0415

    match = re.search(r"or HTTP ((?:\d{3}(?:, | or ))*\d{3})\.", OPERATIONS.read_text())
    assert match, "the retry paragraph must list the retried codes as 'or HTTP a, b or c.'"
    codes = {int(code) for code in re.split(r", | or ", match.group(1))}
    assert codes == fetch._TRANSIENT_HTTP_CODES


def test_operations__release_schedule__matches_the_workflow_cron():
    import yaml  # noqa: PLC0415

    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "kb-release.yml").read_text())
    cron = workflow.get("on", workflow.get(True))["schedule"][0]["cron"]
    minute, hour, _day, _month, weekday = cron.split()
    match = re.search(r"every (\w+day) at (\d{2}):(\d{2}) UTC", OPERATIONS.read_text())
    assert match, "the schedule must read 'every <weekday> at HH:MM UTC'"
    days = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")
    assert days.index(match.group(1)) == int(weekday) % 7  # cron: 0 and 7 are both Sunday
    assert (int(match.group(2)), int(match.group(3))) == (int(hour), int(minute))


def test_operations__install_section__exists_under_the_heading_the_install_guide_names():
    # Containment is exact here: the install guide quotes the whole heading, so no shorter or
    # longer heading can satisfy it the way a number can sit inside a larger one.
    assert f'"{_INSTALL_HEADING}"' in INSTALL.read_text(), "docs/install.md must still name this heading"
    assert _section(OPERATIONS.read_text(), _INSTALL_HEADING).strip()


def test_operations__install_commands__parse_with_the_installer_flags(monkeypatch):
    import shlex  # noqa: PLC0415

    from stig_mcp.kb import install  # noqa: PLC0415

    calls = []
    monkeypatch.setattr(install, "install_file", lambda *args, **kwargs: calls.append("file") or {})
    monkeypatch.setattr(install, "install_release", lambda *args, **kwargs: calls.append("release") or {})
    commands = re.findall(
        r"^\s*(uv run stig-mcp-install-kb\b.*)$", _section(OPERATIONS.read_text(), _INSTALL_HEADING), re.M
    )
    assert len(commands) >= 3, "the section must show the plain, --release and --file installs"
    for command in commands:
        assert install.main(shlex.split(command)[3:]) == 0, command
    assert set(calls) == {"file", "release"}


def test_operations__asset_name_example__carries_the_current_schema():
    from stig_mcp.kb.db import SCHEMA_VERSION  # noqa: PLC0415

    body = _section(OPERATIONS.read_text(), _INSTALL_HEADING)
    schemas = re.findall(r"stig_kb-schema(\d+)-\d{4}-\d{2}-\d{2}\.sqlite", body)
    assert schemas, "the section must spell an example asset name"
    assert {int(schema) for schema in schemas} == {int(SCHEMA_VERSION)}


PRIVACY = ROOT / "PRIVACY.md"
RELEASING = ROOT / "RELEASING.md"


def _privacy_hosts(heading):
    body = _section(PRIVACY.read_text(), heading)
    listed = _listed_hosts(body)
    assert listed, f"the {heading!r} section must write each host as a code span"
    return listed


def test_privacy__server_section__lists_exactly_the_release_hosts():
    expected = _hosts(ROOT / "stig_mcp" / "kb") | set(releases.ASSET_REDIRECT_HOSTS)
    assert _privacy_hosts("The MCP server") == expected


def test_privacy__fetch_section__lists_exactly_the_fetch_hosts():
    assert _privacy_hosts("Building the knowledge base yourself") == _hosts(ROOT / "stig_mcp" / "ingest")


def test_privacy__both_sections__cover_every_host_the_package_contacts():
    both = _privacy_hosts("The MCP server") | _privacy_hosts("Building the knowledge base yourself")
    assert both == _hosts(ROOT / "stig_mcp") | set(releases.ASSET_REDIRECT_HOSTS)


def test_privacy__server_section__says_the_os_may_contact_certificate_authorities():
    body = " ".join(_section(PRIVACY.read_text(), "The MCP server").split())
    assert "Certificate verification" in body and "uses the operating system" in body
    assert "certificate authorities' servers" in body


def test_privacy__user_agent__matches_what_every_request_sends():
    from stig_mcp.ingest import catalog, upstream  # noqa: PLC0415

    sent = {releases.USER_AGENT, catalog.USER_AGENT, upstream.USER_AGENT}
    assert len(sent) == 1, "the sections below state one User-Agent for all requests"
    stated = re.findall(r"`User-Agent` of `([^`]+)`", PRIVACY.read_text())
    assert stated, "PRIVACY.md must state the User-Agent as a `User-Agent` of `value`"
    assert set(stated) == sent


BLOB = "https://github.com/jeneric/STIG-MCP/blob/main/"


def test_readme__links__are_absolute_so_the_pypi_page_can_follow_them():
    targets = re.findall(r"\]\(([^)\s]+)\)", README.read_text())
    assert targets, "no links found, so this test would pass on an empty README"
    assert [t for t in targets if not t.startswith(("https://", "#"))] == []


def test_readme__repository_links__name_files_that_exist():
    paths = re.findall(rf"\]\({re.escape(BLOB)}([^)#\s]+)", README.read_text())
    assert paths, "the README links into the repository, so none found means the pattern broke"
    assert [p for p in paths if not (ROOT / p).exists()] == []


def test_privacy__readme__links_to_it_from_the_fetch_list_and_the_documentation_list():
    readme = README.read_text()
    assert f"]({BLOB}PRIVACY.md)" in _section(readme, "What this server fetches")
    assert f"]({BLOB}PRIVACY.md)" in _section(readme, "Documentation")


def test_security__scope__covers_the_release_pipeline():
    # A containment check is right here: the values are file paths, not numbers.
    scope = _section((ROOT / "SECURITY.md").read_text(), "Scope")
    assert ".github/workflows/kb-release.yml" in scope
    assert "tools/kb_" in scope
    assert ".github/workflows/publish.yml" in scope
    assert "tools/publish_check.py" in scope


def _publisher_field(field):
    section = _section(RELEASING.read_text(), "Publishing the package")
    row = re.search(rf"^\| {re.escape(field)} \| (.+) \|$", section, re.M)
    assert row, f"the publishing table must have a {field!r} row"
    return re.findall(r"`([^`]+)`", row.group(1))


def test_releasing__publisher_table__names_the_workflow_and_environments_it_uses():
    import yaml  # noqa: PLC0415

    workflow = ROOT / ".github" / "workflows" / "publish.yml"
    jobs = yaml.safe_load(workflow.read_text())["jobs"]
    assert _publisher_field("Workflow name") == [workflow.name]
    assert _publisher_field("Environment name") == [jobs["testpypi"]["environment"], jobs["pypi"]["environment"]]
    assert _publisher_field("PyPI project name") == ["stig-mcp"]


def _actor_section():
    return _section(GUIDE.read_text(), "How does it match the actor I named?")


def test_user_guide__quoted_misspelling_error__is_what_the_tool_raises(kb_path):
    quoted = re.search(r"^    (Unknown actor 'Cosy Bear'.*)$", _actor_section(), re.M)
    assert quoted, "the actor section must quote the misspelling error for 'Cosy Bear'"
    try:
        tools.techniques_for_actor(app_module.KnowledgeBase(kb_path), "Cosy Bear")
    except tools.CallerError as error:
        assert str(error) == quoted.group(1)
    else:
        raise AssertionError("'Cosy Bear' must not resolve")


def test_user_guide__loose_examples__each_resolve(kb_path):
    # Only the ones the fixture knowledge base holds; it has APT29 alone.
    examples = re.findall(r"`([^`]+)`", _actor_section().split("all resolve")[0])
    kb = app_module.KnowledgeBase(kb_path)
    for typed in ("apt 29", "Cozybear", "G-0016"):
        assert typed in examples
        assert tools.techniques_for_actor(kb, typed)["actor"]["id"] == "G0016"


def test_user_guide__tools_list__names_every_registered_tool_with_its_parameters(tmp_path):
    import asyncio  # noqa: PLC0415

    listed = {
        name: {p.strip().rstrip("?") for p in params.split(",") if p.strip()}
        for name, params in re.findall(r"^- `(\w+)\(([^)]*)\)`", _section(GUIDE.read_text(), "Tools"), re.M)
    }
    registered = {
        tool.name: set(tool.input_schema.get("properties", {}))
        for tool in asyncio.run(app_module.build_server(tmp_path / "absent.sqlite").list_tools())
    }
    assert listed == registered


_VSCODE_BADGE = re.compile(r"\]\((https://(?:insiders\.)?vscode\.dev/redirect/mcp/install\?[^)\s]+)\)")


def _json_block(text, heading):
    return json.loads(re.search(r"```json\n(.*?)```", _section(text, heading), re.S).group(1))


def test_readme__vscode_badges__install_the_documented_configuration():
    documented = _json_block(INSTALL.read_text(), "Configuring by hand")["servers"]["stig-mcp"]
    links = _VSCODE_BADGE.findall(_section(README.read_text(), "VS Code (GitHub Copilot)"))
    assert links, "the README's VS Code quick start has no install badge"
    for link in links:
        query = parse_qs(urlparse(link).query)
        assert query["name"] == ["stig-mcp"]
        assert (
            json.loads(query["config"][0])
            == documented
            == {
                "type": "stdio",
                "command": "uvx",
                "args": ["stig-mcp"],
                "env": {"UV_SYSTEM_CERTS": "true", "UV_NATIVE_TLS": "true"},
            }
        )


PLUGIN_MCP = ROOT / "plugins" / "stig-mcp" / ".mcp.json"


def test_docs__every_uvx_config__carries_the_plugin_env_pair():
    plugin_env = json.loads(PLUGIN_MCP.read_text())["mcpServers"]["stig-mcp"]["env"]
    guide = INSTALL.read_text()
    assert _json_block(guide, "Configuring by hand")["servers"]["stig-mcp"]["env"] == plugin_env
    other = _json_block(README.read_text(), "Other MCP clients")["mcpServers"]["stig-mcp"]
    assert other == {"command": "uvx", "args": ["stig-mcp"], "env": plugin_env}
    adds = re.findall(r"^\s*claude mcp add stig-mcp .*uvx stig-mcp$", guide, re.M)
    assert adds, "docs/install.md has no `claude mcp add` line for uvx, so nothing was checked"
    for line in adds:
        assert all(f"-e {key}={value}" in line for key, value in plugin_env.items()), line


def test_install__corporate_note__names_both_uv_settings():
    note = _section(INSTALL.read_text(), "Behind a TLS-inspecting proxy")
    assert "UV_SYSTEM_CERTS" in note and "UV_NATIVE_TLS" in note
    assert "system-certs = true" in note
    assert "native-tls = true" in note
    assert "0.11" in note


def test_install__corporate_note__names_the_ca_file_variables_and_where_they_apply():
    note = " ".join(_section(INSTALL.read_text(), "Behind a TLS-inspecting proxy").split())
    assert "`SSL_CERT_FILE`" in note
    assert "`SSL_CERT_DIR` is honored only on Linux" in note


def test_install__corporate_note__drops_the_pair_where_the_os_store_is_empty():
    note = _section(INSTALL.read_text(), "Behind a TLS-inspecting proxy")
    assert "ca-certificates" in note
    assert "every configuration above" not in note


def test_readme__sections__lead_with_the_prerequisite_quick_start_and_prompts():
    headings = re.findall(r"^## (.+)$", README.read_text(), re.M)
    assert headings[:4] == ["Prerequisite", "Quick start", "Example prompts", "Other MCP clients"]


def test_readme__each_quick_start__links_its_section_of_the_install_guide():
    readme = README.read_text()
    for heading, anchor in (("VS Code (GitHub Copilot)", "vs-code-github-copilot"), ("Claude Code", "claude-code")):
        assert f"]({BLOB}docs/install.md#{anchor})" in _section(readme, heading), heading


def _slug(heading):
    """GitHub's anchor for a markdown heading: lowercase, punctuation dropped, spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def test_slug__a_heading_with_punctuation__matches_githubs_anchor():
    assert _slug("VS Code (GitHub Copilot)") == "vs-code-github-copilot"
    assert _slug("The server does not start: `uvx` not found") == "the-server-does-not-start-uvx-not-found"


def _headings(doc):
    """(level, text, anchor) for each heading outside code fences, with GitHub's -1, -2 suffix
    on a repeated anchor."""
    found, seen, fenced = [], {}, False
    for line in doc.read_text().splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
        match = None if fenced else re.match(r"^(#+) (.+)$", line)
        if match:
            base = _slug(match.group(2))
            anchor = f"{base}-{seen[base]}" if base in seen else base
            seen[base] = seen.get(base, 0) + 1
            found.append((len(match.group(1)), match.group(2), anchor))
    return found


def _anchors(doc):
    return {anchor for _level, _text, anchor in _headings(doc)}


def test_headings__a_repeated_heading__gets_githubs_numbered_anchor(tmp_path):
    doc = tmp_path / "doc.md"
    doc.write_text("## A\n\n```\n# not a heading\n```\n\n### Same\n\n### Same\n")
    assert [anchor for _level, _text, anchor in _headings(doc)] == ["a", "same", "same-1"]


_CONTENTS = re.compile(r"^( *)- \[(.+)\]\(#([^)]+)\)$", re.M)


@pytest.mark.parametrize("name", ["install.md", "user-guide.md", "operations.md"])
def test_contents__each_long_doc__lists_every_section_in_order(name):
    doc = ROOT / "docs" / name
    listed = [
        (len(indent) // 2 + 2, text, anchor)
        for indent, text, anchor in _CONTENTS.findall(_section(doc.read_text(), "Contents"))
    ]
    expected = [heading for heading in _headings(doc) if heading[0] in (2, 3) and heading[1] != "Contents"]
    assert listed == expected


def test_docs__anchored_links__name_a_heading_in_their_target():
    links = []
    for doc in [README, *(ROOT / "docs").glob("*.md"), ROOT / "PRIVACY.md"]:
        for target, anchor in re.findall(r"\]\(([^)#\s]*)#([^)\s]+)\)", doc.read_text()):
            path = (
                (ROOT / target.removeprefix(BLOB))
                if target.startswith(BLOB)
                else (doc.parent / target if target else doc)
            )
            if target.startswith("http") and not target.startswith(BLOB):
                continue
            links.append((doc.name, target, anchor, path))
    assert len(links) >= 10, "too few anchored links found, so the pattern probably broke"
    broken = [f"{doc} -> {target}#{anchor}" for doc, target, anchor, path in links if anchor not in _anchors(path)]
    assert broken == []


def test_install__organization_allowlist__quotes_the_message_vs_code_shows():
    troubleshooting = _section(INSTALL.read_text(), "Troubleshooting")
    message = "This Model Context Protocol server is not in the list of servers allowed by your organization"
    assert f'### "{message}"' in troubleshooting
    assert "chat.mcp.allowedServers" in troubleshooting


def test_install__proxy_timeout__names_the_uv_setting():
    body = _section(INSTALL.read_text(), "Downloads time out behind a proxy")
    assert "`UV_HTTP_TIMEOUT`" in body


_DEFENSES_HEADING = "Protect and Detect: ATT&CK mitigations and detections"


def test_user_guide__defense_details_bound__matches_the_code():
    body = _section(GUIDE.read_text(), _DEFENSES_HEADING)
    match = re.search(r"`defense_details` takes up to (\d+) ids", body)
    assert match and int(match.group(1)) == tools._MAX_DEFENSE_IDS


def test_user_guide__log_sources_bound__matches_the_code():
    body = _section(GUIDE.read_text(), _DEFENSES_HEADING)
    # "up to", not "at most": test_app's benchmark_ids guard reads every "at most N" in the guide.
    match = re.search(r"`log_sources` takes up to (\d+) names", body)
    assert match and int(match.group(1)) == tools._MAX_LOG_SOURCES


def test_user_guide__coverage_keys__match_a_real_answer(defenses_kb):
    body = _section(GUIDE.read_text(), _DEFENSES_HEADING)
    documented = set(re.findall(r"^- `([a-z_]+)`:", body, re.M))
    kb = app_module.KnowledgeBase(defenses_kb)
    result = tools.techniques_for_actor(
        kb,
        "APT29",
        system_description="RHEL 9",
        include_defenses=True,
        platforms=["Windows"],
        log_sources=["WinEventLog:Security"],
    )
    assert set(result["summary"]["coverage"]) == documented


def test_descriptions__every_manifest__names_mitigations_and_detections():
    for path in (
        ROOT / "server.json",
        ROOT / "plugins" / "stig-mcp" / ".claude-plugin" / "plugin.json",
        ROOT / ".claude-plugin" / "marketplace.json",
    ):
        text = path.read_text()
        assert "mitigations" in text and "detections" in text, path
    assert "detections" in (ROOT / "plugins" / "stig-mcp" / "README.md").read_text()
