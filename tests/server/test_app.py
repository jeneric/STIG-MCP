import asyncio
import hashlib
import json
import logging
import lzma
import os
import re
import shutil
import sqlite3
import threading
from pathlib import Path

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from stig_mcp.ingest import config
from stig_mcp.kb.db import create_db
from stig_mcp.server import app as app_module
from stig_mcp.server import tools
from stig_mcp.server.app import build_server
from tests.conftest import open_db_for_test


@pytest.fixture(autouse=True)
def _close_the_connections_the_holder_opens(monkeypatch):
    """A KnowledgeBase opens a connection on first use and holds it until the file changes
    underneath it, which is right for the real server and a leak here, where the module builds
    a couple of dozen of them and abandons each one. Routing app.py's open_db through the test
    helper hands every connection to the teardown that closes it, whether the holder closed it
    itself or not; sqlite3's close is idempotent, so a double close is harmless."""
    monkeypatch.setattr(app_module, "open_db", open_db_for_test)


def test_build_server__a_knowledge_base_at_the_wrong_schema__starts_and_reports_it_per_call(tmp_path):
    # build_server rejects nothing, because a server that exits explains nothing to a VS Code
    # user; the holder reports "schema_outdated" per call instead, and nothing is ever answered
    # from the stale file.
    db = tmp_path / "stale.sqlite"
    conn = create_db(db)
    conn.execute("INSERT INTO ingest_meta (source_name, schema_version) VALUES ('test', '1')")
    conn.commit()
    conn.close()
    server = build_server(db)
    assert "defenses_for_technique" in {t.name for t in asyncio.run(server.list_tools())}
    held, reason = app_module.KnowledgeBase(db).acquire()
    assert held is None and reason == "schema_outdated"


def test_build_server__valid_kb__registers_nine_tools(kb_path):
    server = build_server(kb_path)
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    # Equality, not `<=`: a subset assertion passes with a tenth tool registered, and the tool list is
    # the server's whole published surface. The name says nine, so the test should hold it to nine.
    assert names == {
        "defenses_for_technique",
        "techniques_for_actor",
        "finding_details",
        "defense_details",
        "resolve_system",
        "search_techniques",
        "list_stigs",
        "check_sources",
        "install_knowledge_base",
    }


def test_build_server__list_stigs_description__advertises_id_and_keyword_matching(kb_path):
    # The docstring is published verbatim as the MCP tool description, so it is the
    # only thing telling a caller that a stig_id from resolve_system is a valid
    # filter. If it says only "title", id and keyword matching is unreachable in
    # practice.
    server = build_server(kb_path)
    tools = asyncio.run(server.list_tools())
    description = next(t.description for t in tools if t.name == "list_stigs")
    assert "benchmark id" in description.lower()
    assert "keyword" in description.lower()


def test_build_server__list_stigs_tool_called__forwards_the_filter(kb_path):
    # Goes through the registered tool rather than queries.list_stigs, which is the path
    # an MCP client takes and the only thing covering the tool body. Asserting a filtered
    # result also proves the argument is forwarded rather than dropped.
    server = build_server(kb_path)
    blocks = asyncio.run(server.call_tool("list_stigs", {"filter": "RHEL"})).content
    assert [json.loads(b.text)["stig_id"] for b in blocks] == ["RHEL_9_STIG"]


def test_build_server__list_stigs_tool_called_without_filter__returns_every_benchmark(kb_path):
    server = build_server(kb_path)
    blocks = asyncio.run(server.call_tool("list_stigs", {})).content
    assert {json.loads(b.text)["stig_id"] for b in blocks} == {
        "RHEL_9_STIG",
        "MS_Windows_Server_2022_STIG",
    }


def test_build_server__tool_body_raises_an_unexpected_value_error__returns_only_the_generic_error(kb_path, monkeypatch):
    # Only the deliberate guidance type crosses as ToolError. Any other ValueError is a bug or a
    # broken file, and its text (which may quote an install path) must stay in the server log.
    def broken(kb, filter):
        raise ValueError("internal invariant broke at /home/someone/private/path")

    monkeypatch.setattr(tools, "list_stigs", broken)
    server = build_server(kb_path)
    with pytest.raises(ToolError) as caught:
        asyncio.run(server.call_tool("list_stigs", {}))
    assert str(caught.value) == "Error executing tool list_stigs"


def test_build_server__every_tool_called__reads_the_knowledge_base_on_the_event_loop_thread(
    kb_path, tmp_path, monkeypatch
):
    # MCPServer runs a sync tool on a worker thread, and KnowledgeBase caches one sqlite3
    # connection, which refuses use from any thread but the one that opened it. So every tool
    # must reach the holder on the event loop's thread; one that does not fails on a later call.
    # Served from a COPY of kb_path: kb_path is session-scoped, and install_knowledge_base
    # below replaces the file it is given.
    from stig_mcp.kb import releases  # noqa: PLC0415
    from tests.kb.fake_github import FakeGitHub  # noqa: PLC0415

    monkeypatch.setattr(releases, "default_opener", FakeGitHub)
    live = tmp_path / "kb.sqlite"
    shutil.copyfile(kb_path, live)
    xz = tmp_path / "kb.sqlite.xz"
    xz.write_bytes(lzma.compress(kb_path.read_bytes()))
    xz_sha = hashlib.sha256(xz.read_bytes()).hexdigest()
    acquired_on = []
    released_on = []
    real_acquire = app_module.KnowledgeBase.acquire
    real_release = app_module.KnowledgeBase.release

    def recording_acquire(self):
        acquired_on.append(threading.get_ident())
        return real_acquire(self)

    def recording_release(self):
        released_on.append(threading.get_ident())
        return real_release(self)

    monkeypatch.setattr(app_module.KnowledgeBase, "acquire", recording_acquire)
    monkeypatch.setattr(app_module.KnowledgeBase, "release", recording_release)
    server = build_server(live)
    calls = {
        "defenses_for_technique": {"technique_id": "T1078"},
        "techniques_for_actor": {"actor": "Cozy Bear"},
        "resolve_system": {"system_description": "RHEL 9"},
        "search_techniques": {"query": "valid accounts"},
        "list_stigs": {},
        "check_sources": {},
        "finding_details": {"ids": ["V-100001"]},
        "defense_details": {"ids": ["M1026"]},
        "install_knowledge_base": {"path": str(xz), "sha256": xz_sha},
    }

    async def call_every_tool():
        for name, arguments in calls.items():
            await server.call_tool(name, arguments)
        return threading.get_ident()

    loop_thread = asyncio.run(call_every_tool())
    assert {t.name for t in asyncio.run(server.list_tools())} == set(calls)
    # install_knowledge_base only releases the holder and never acquires it.
    assert len(acquired_on) == len(calls) - 1
    assert set(acquired_on) == {loop_thread}
    assert released_on and set(released_on) == {loop_thread}


def test_build_server__initialize__reports_the_stig_mcp_package_version():
    # The MCP SDK reports an empty server version unless told; a client should see which
    # stig-mcp it is talking to.
    from importlib.metadata import version  # noqa: PLC0415

    from mcp import Client  # noqa: PLC0415

    async def server_info():
        async with Client(build_server(Path("/nonexistent/kb.sqlite"))) as client:
            return client.server_info

    assert asyncio.run(server_info()).version == version("stig-mcp")


def _call(server, name, arguments):
    """Invoke a registered tool the way an MCP client does and return its single block.

    MCPServer emits one content block per list element, so this is only safe for the
    dict-returning tools. The assertion stops a later caller from pointing it at a
    list-returning tool and believing they checked the whole result set.
    """
    blocks = asyncio.run(server.call_tool(name, arguments)).content
    assert len(blocks) == 1, f"{name} returned {len(blocks)} blocks; _call would hide all but the first"
    return json.loads(blocks[0].text)


def test_build_server__list_stigs_tool_called_with_no_knowledge_base__crosses_the_not_ready_dict_intact(
    tmp_path, monkeypatch
):
    # list_stigs is annotated `-> list`, and MCPServer derives an output schema
    # from a return annotation. If it built one here, the not_ready dict tools.list_stigs
    # returns instead of a list would be rejected at the boundary: a failed tool call in
    # VS Code, the exact outcome this design prevents.
    #
    # _call is safe here even though it refuses list-returning tools: not_ready collapses
    # list_stigs to a single dict, so exactly one content block comes back, the same shape
    # _call already requires for the dict-returning tools.
    #
    # SOURCES_DIR is monkeypatched because readiness.payload reads it unconditionally: without
    # this every reason-reaching test scans the real sources directory of whoever runs it.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    server = build_server(tmp_path / "absent.sqlite")
    payload = _call(server, "list_stigs", {})
    assert payload["status"] == "not_ready"
    assert payload["reason"] == "no_knowledge_base"
    assert payload["next"]


def test_build_server__search_techniques_tool_called_with_no_knowledge_base__crosses_the_not_ready_dict_intact(
    tmp_path, monkeypatch
):
    # search_techniques' other half of the same annotation risk.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    server = build_server(tmp_path / "absent.sqlite")
    payload = _call(server, "search_techniques", {"query": "valid accounts"})
    assert payload["status"] == "not_ready"
    assert payload["reason"] == "no_knowledge_base"
    assert payload["next"]


def test_build_server__defenses_tool_called__scopes_to_the_described_system(kb_path):
    # These exercise the registered tool bodies, which the direct tools.<name> tests
    # never reach. Where a test passes an optional argument it asserts a result only
    # the forwarded argument produces, so dropping the argument fails the test; the
    # two that pass none pin the happy path through the registered tool instead.
    server = build_server(kb_path)
    payload = _call(
        server,
        "defenses_for_technique",
        {"technique_id": "T1078", "system_description": "Red Hat Enterprise Linux 9"},
    )
    assert payload["technique"]["id"] == "T1078"
    assert [s["stig_id"] for s in payload["resolved_systems"]] == ["RHEL_9_STIG"]


@pytest.mark.parametrize(
    ("name", "arguments", "guidance"),
    [
        (
            "defenses_for_technique",
            {"technique_id": "T9999"},
            "Unknown technique_id 'T9999'. Call search_techniques",
        ),
        (
            "techniques_for_actor",
            {"actor": "No Such Group"},
            "Unknown actor 'No Such Group'. Provide an ATT&CK group id",
        ),
        (
            "defenses_for_technique",
            {"technique_id": "T1078", "benchmark_ids": [f"S{i}" for i in range(201)]},
            "benchmark_ids names 201 benchmarks, over the limit of 200",
        ),
    ],
    ids=["unknown_technique", "unknown_actor", "too_many_benchmark_ids"],
)
def test_build_server__tool_rejects_its_arguments__surfaces_the_guidance(kb_path, name, arguments, guidance):
    # MCPServer replaces an ordinary exception's message with "Error executing tool ...", so a
    # ValueError's guidance reaches the caller only because the tool re-raises it as ToolError.
    server = build_server(kb_path)
    with pytest.raises(ToolError, match=re.escape(guidance)):
        asyncio.run(server.call_tool(name, arguments))


def test_build_server__techniques_for_actor_tool_called__resolves_the_alias(kb_path):
    server = build_server(kb_path)
    payload = _call(server, "techniques_for_actor", {"actor": "Cozy Bear"})
    assert payload["actor"]["id"] == "G0016"
    assert [t["technique_id"] for t in payload["techniques"]] == ["T1078"]


def test_build_server__techniques_for_actor_tool_given_a_misspelling__suggests_the_group(kb_path):
    server = build_server(kb_path)
    with pytest.raises(ToolError, match=re.escape("Closest ATT&CK groups: APT29 (G0016, as 'Cozy Bear')")):
        asyncio.run(server.call_tool("techniques_for_actor", {"actor": "Cosy Bear"}))


def test_build_server__techniques_for_actor_tool_given_loose_spacing__resolves_and_says_so(kb_path):
    server = build_server(kb_path)
    payload = _call(server, "techniques_for_actor", {"actor": "APT 29"})
    assert payload["actor"]["id"] == "G0016"
    assert payload["actor"]["matched_as"] == "APT29"


def test_build_server__defenses_tool_called_with_explicit_benchmark_ids__uses_them_as_scope(kb_path):
    server = build_server(kb_path)
    payload = _call(
        server,
        "defenses_for_technique",
        {"technique_id": "T1078", "benchmark_ids": ["RHEL_9_STIG"]},
    )
    assert [s["stig_id"] for s in payload["resolved_systems"]] == ["RHEL_9_STIG"]


def test_build_server__techniques_for_actor_tool_called_with_defenses__expands_them(kb_path):
    server = build_server(kb_path)
    payload = _call(
        server,
        "techniques_for_actor",
        {"actor": "Cozy Bear", "system_description": "Red Hat Enterprise Linux 9", "include_defenses": True},
    )
    assert payload["techniques"][0]["controls"]
    assert payload["findings"]


def test_build_server__resolve_system_tool_called__honors_the_limit(kb_path):
    # Two fragments, one per fixture benchmark, so the count is sensitive to limit. A single-match
    # description would make this assertion vacuous.
    server = build_server(kb_path)
    unlimited = _call(server, "resolve_system", {"system_description": "Windows Server 2022 and RHEL 9"})
    assert len(unlimited["candidates"]) == 2
    limited = _call(server, "resolve_system", {"system_description": "Windows Server 2022 and RHEL 9", "limit": 1})
    assert len(limited["candidates"]) == 1


def test_build_server__search_techniques_tool_called__finds_by_name(kb_path):
    server = build_server(kb_path)
    payload = _call(server, "search_techniques", {"query": "valid accounts"})
    assert payload["technique_id"] == "T1078"


def test_build_server__search_techniques_tool_called__honors_the_limit(kb_path):
    # "accounts" matches T1078 and T1078.001 in the fixture.
    server = build_server(kb_path)
    unlimited = asyncio.run(server.call_tool("search_techniques", {"query": "accounts"})).content
    assert len(unlimited) == 2
    limited = asyncio.run(server.call_tool("search_techniques", {"query": "accounts", "limit": 1})).content
    assert len(limited) == 1


def _stub_transport(monkeypatch):
    """Replace the stdio transport with a recorder, so main() returns instead of serving.

    Records the transport name rather than the server object. main() passes none and takes
    MCPServer's default, so the recorder has to supply the same default to see it at all; the
    tests below assert `["stdio"]`, which a recorder of server objects cannot express.
    """
    served = []
    monkeypatch.setattr(MCPServer, "run", lambda self, transport="stdio", **kwargs: served.append(transport))
    return served


def test_main__valid_kb__starts_the_server(kb_path, monkeypatch):
    monkeypatch.setattr(config, "KB_PATH", kb_path)
    served = _stub_transport(monkeypatch)
    app_module.main()
    assert served == ["stdio"]


def test_main__schema_stale_kb__warns_and_starts_anyway(kb_path, tmp_path, monkeypatch, caplog):
    # A stale schema is the discriminating case for the warning, because open_db opens the file
    # happily and only the schema read tells it apart from a healthy knowledge base; a missing
    # file would leave the message untested against anything open_db does not already reject.
    # The state name is asserted so the operator learns which of the three reasons applies, not
    # merely that something is wrong.
    stale = tmp_path / "stale.sqlite"
    stale.write_bytes(kb_path.read_bytes())
    conn = sqlite3.connect(stale)
    conn.execute("UPDATE ingest_meta SET schema_version = '999'")
    conn.commit()
    conn.close()

    monkeypatch.setattr(config, "KB_PATH", stale)
    served = _stub_transport(monkeypatch)
    with caplog.at_level(logging.WARNING):
        app_module.main()
    assert served == ["stdio"]
    # getMessage(), not .message: the reason is a lazy %s argument, so only the interpolated
    # form contains it, and interpolating an already-formatted .message raises instead.
    #
    # The reason is matched WITH its parentheses. The message names the knowledge base path,
    # and pytest builds that path out of the test's own name, so a bare substring match is
    # answered by the path rather than by the reason: the unreadable test below would pass with a
    # constant logged, because its tmp_path spells "unreadable".
    assert any("not usable yet" in rec.getMessage() for rec in caplog.records)
    assert any("(schema_outdated)" in rec.getMessage() for rec in caplog.records)


def test_main__unreadable_kb__warns_and_starts_anyway(tmp_path, monkeypatch, caplog):
    # The server must start so its tools can explain themselves; an unreadable knowledge base
    # is reported per call as reason "unreadable".
    corrupt = tmp_path / "corrupt.sqlite"
    corrupt.write_bytes(b"not a database, just bytes")
    monkeypatch.setattr(config, "KB_PATH", corrupt)
    served = _stub_transport(monkeypatch)
    with caplog.at_level(logging.WARNING):
        app_module.main()
    assert served == ["stdio"]
    assert any("not usable yet" in rec.getMessage() for rec in caplog.records)
    # Parenthesized, for the reason given at the stale-schema test above: this test's own
    # tmp_path contains the word "unreadable", so the bare substring is vacuous here.
    assert any("(unreadable)" in rec.getMessage() for rec in caplog.records)


def test_build_server__mitigations_description__advertises_revoked_id_handling(kb_path):
    server = build_server(kb_path)
    tools_listed = asyncio.run(server.list_tools())
    description = next(t.description for t in tools_listed if t.name == "defenses_for_technique")
    assert "revoked" in description.lower()
    assert "redirected_from" in description


def test_build_server__defenses_description__tells_the_agent_a_build_is_meaningful(kb_path):
    server = build_server(kb_path)
    tools_listed = asyncio.run(server.list_tools())
    description = next(t.description for t in tools_listed if t.name == "defenses_for_technique")
    assert "build" in description.lower()
    assert "8.0 U3" in description


def test_build_server__resolve_system_description__tells_the_agent_a_build_is_meaningful(kb_path):
    server = build_server(kb_path)
    tools_listed = asyncio.run(server.list_tools())
    description = next(t.description for t in tools_listed if t.name == "resolve_system")
    assert "build" in description.lower()


def test_build_server__defenses_tool_called_with_a_revoked_id__redirects(kb_path):
    server = build_server(kb_path)
    payload = _call(server, "defenses_for_technique", {"technique_id": "T8001"})
    assert payload["technique"]["id"] == "T9000"
    assert payload["technique"]["redirected_from"] == "T8001"


def test_build_server__search_description__advertises_revoked_matching(kb_path):
    server = build_server(kb_path)
    tools_listed = asyncio.run(server.list_tools())
    description = next(t.description for t in tools_listed if t.name == "search_techniques")
    assert "revoked" in description.lower()


def test_build_server__search_tool_called_with_a_revoked_id__returns_the_replacement(kb_path):
    server = build_server(kb_path)
    payload = _call(server, "search_techniques", {"query": "T8001"})
    assert payload["technique_id"] == "T9000"
    assert payload["redirected_from"] == "T8001"


def test_build_server__no_knowledge_base__still_starts_and_lists_tools(tmp_path):
    # The whole design rests on this. A server that exits is a red indicator in VS Code
    # with the reason behind an output pane; a server that starts can explain itself.
    server = build_server(tmp_path / "absent.sqlite")
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert "defenses_for_technique" in names


def test_knowledge_base__a_kb_appearing_after_start__is_picked_up_without_a_restart(tmp_path, kb_path):
    # The expected bootstrap flow: server starts empty, the agent runs the ingest, the user
    # asks again. Requiring a restart would mean reloading the VS Code window.
    later = tmp_path / "kb.sqlite"
    holder = app_module.KnowledgeBase(later)
    conn, reason = holder.acquire()
    assert conn is None and reason == "no_knowledge_base"
    later.write_bytes(kb_path.read_bytes())
    conn, reason = holder.acquire()
    assert reason is None and conn is not None


def _rebuild(live, replacement):
    """Replace the knowledge base the way the ingest does, rather than the way a test finds
    convenient. Both tests below need this to be the real thing.

    `live.write_bytes(...)` rewrites the SAME inode, and a held connection then reads the NEW
    content, so it does not reproduce the hazard at all: a build_server that acquires one
    connection at startup passes a write_bytes version of these tests. Only a new inode under
    the same name leaves a stale connection reading stale data.
    """
    incoming = live.parent / f"{live.name}.incoming"
    incoming.write_bytes(replacement.read_bytes())
    os.replace(incoming, live)  # what the ingest does: a new inode under the same name


def test_knowledge_base__a_rebuilt_kb__is_not_answered_from_the_old_connection(tmp_path, kb_path, wide_kb):
    # The recorded hazard: the ingest replaces the file atomically, so a held read-only
    # connection keeps reading the inode it opened. Pinned at the resolver level already;
    # this pins it where the connection is actually held.
    live = tmp_path / "kb.sqlite"
    live.write_bytes(kb_path.read_bytes())
    holder = app_module.KnowledgeBase(live)
    first, _ = holder.acquire()
    _rebuild(live, wide_kb)
    second, _ = holder.acquire()
    assert second is not first


def test_build_server__a_kb_rebuilt_while_the_server_runs__is_answered_from_the_new_one(tmp_path, kb_path, wide_kb):
    # What the holder is FOR, through the registered tool, which is the only thing that can
    # tell a per-call acquire from a connection captured once at build time. Every other test
    # here passes against a build_server that acquires once and closes over the result.
    live = tmp_path / "kb.sqlite"
    live.write_bytes(kb_path.read_bytes())
    server = build_server(live)
    before = len(asyncio.run(server.call_tool("list_stigs", {})).content)
    _rebuild(live, wide_kb)
    after = len(asyncio.run(server.call_tool("list_stigs", {})).content)
    assert after > before


def test_knowledge_base__an_unchanged_kb__reuses_the_same_connection(kb_path):
    # The other half of the identity check. Without this, reopening on every call passes the
    # rebuild test above while costing a fresh open per tool call.
    holder = app_module.KnowledgeBase(kb_path)
    first, _ = holder.acquire()
    second, _ = holder.acquire()
    assert second is first


def test_knowledge_base__a_kb_that_disappears__closes_the_connection_it_handed_out(tmp_path, kb_path):
    # The third transition, and the only one that can leak: READY then not. A connection is
    # asserted CLOSED rather than merely dropped, because SQLite keeps serving a file that has
    # been unlinked, so a holder that only forgot its reference would still be answering from
    # a knowledge base that no longer exists, and no identity check would ever fire again.
    live = tmp_path / "kb.sqlite"
    live.write_bytes(kb_path.read_bytes())
    holder = app_module.KnowledgeBase(live)
    first, _ = holder.acquire()
    live.unlink()
    assert holder.acquire() == (None, "no_knowledge_base")
    with pytest.raises(sqlite3.ProgrammingError):
        first.execute("SELECT 1")


def test_knowledge_base_sha256__no_file__returns_none(tmp_path):
    # Neither answer tool reaches sha256() without _answerable proving the file exists first,
    # so this branch is otherwise unreachable through a tool call; pinned directly.
    assert app_module.KnowledgeBase(tmp_path / "absent.sqlite").sha256() is None


def test_knowledge_base__path__is_read_only(tmp_path):
    # The not-ready payload reads it to name the file in its instructions, so it has to
    # be the path the holder actually opens rather than one a caller can swap underneath it.
    holder = app_module.KnowledgeBase(tmp_path / "kb.sqlite")
    assert holder.path == tmp_path / "kb.sqlite"
    with pytest.raises(AttributeError):
        holder.path = tmp_path / "other.sqlite"


def test_build_server__both_benchmark_ids_descriptions__quote_the_cap_the_code_enforces(kb_path):
    # The limit is written in FOUR places: tools._MAX_BENCHMARK_IDS, the two published tool
    # descriptions that tell an agent about it before it hits the error, and docs/user-guide.md,
    # which is where a human reads it first. Nothing makes them agree, and a published limit
    # that is stale is worse than one that is absent, because the reader will believe it.
    #
    # Every site is checked with the SAME regex, so keep every site phrased "at most N" or this
    # guard silently stops covering one. EXTRACT the number, do not test for containment:
    # `str(200) in "at most 200"` is also true of a cap of 20, of 2 and of 0, and
    # `f"at most {cap}"` has the identical bug, since "at most 20" is a prefix of "at most 200".
    # Lowering is not hypothetical: the comment beside the constant implies a third major of
    # any id brings the cap DOWN. Extraction also fails if a second number creeps into a
    # description.
    server = build_server(kb_path)
    tools_listed = asyncio.run(server.list_tools())
    published = {t.name: t.description for t in tools_listed}
    guide = Path(__file__).parent.parent.parent / "docs" / "user-guide.md"
    published["docs/user-guide.md"] = guide.read_text()
    for name in ("defenses_for_technique", "techniques_for_actor", "docs/user-guide.md"):
        # Every "at most N" must agree, rather than there being exactly one: the guide states
        # the cap and then repeats it in the batching advice. A set comparison still fails on a
        # second, DISAGREEING limit, which is the case worth catching.
        found = re.findall(r"at most (\d+)", published[name])
        assert found, f"{name} no longer states the cap as 'at most {tools._MAX_BENCHMARK_IDS}'"
        assert set(found) == {str(tools._MAX_BENCHMARK_IDS)}, f"{name} advertises {sorted(set(found))}"
        assert "benchmark_ids" in published[name], name


def test_build_server__both_log_sources_descriptions__quote_the_cap_the_code_enforces(kb_path):
    # Phrased "takes up to N names", not "at most N": the benchmark_ids guard above reads every
    # "at most N" in these two descriptions. The number is extracted, not tested for containment.
    published = {t.name: t.description for t in asyncio.run(build_server(kb_path).list_tools())}
    for name in ("defenses_for_technique", "techniques_for_actor"):
        found = re.findall(r"log_sources\s+takes\s+up\s+to\s+(\d+)\s+names", published[name])
        assert found, f"{name} no longer states the log_sources cap"
        assert set(found) == {str(tools._MAX_LOG_SOURCES)}, f"{name} advertises {sorted(set(found))}"


def test_build_server__any_state__lists_check_sources(tmp_path):
    names = {t.name for t in asyncio.run(build_server(tmp_path / "absent.sqlite").list_tools())}
    assert {"check_sources", "defenses_for_technique", "list_stigs"} <= names


def test_build_server__check_sources_tool_called__forwards_to_tools_check_sources(kb_path, monkeypatch):
    # check_sources() takes no arguments, so nothing else here proves the registered tool
    # actually calls tools.check_sources(kb) and returns its result rather than, say, an
    # empty dict. Stubbing tools.check_sources also means this never reaches the network,
    # which the real function would if called with its default opener.
    captured = {}

    def fake_check_sources(kb, opener=None):
        captured["kb"] = kb
        return {"kb_ready": True, "sources_dir": "irrelevant", "report": {}}

    monkeypatch.setattr(tools, "check_sources", fake_check_sources)
    server = build_server(kb_path)
    payload = _call(server, "check_sources", {})
    assert payload == {"kb_ready": True, "sources_dir": "irrelevant", "report": {}}
    assert isinstance(captured["kb"], app_module.KnowledgeBase)


def test_build_server__install_then_answer__first_run_without_a_knowledge_base(tmp_path, kb_path, monkeypatch):
    from stig_mcp.kb import releases  # noqa: PLC0415
    from tests.kb.fake_github import FakeGitHub  # noqa: PLC0415

    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    monkeypatch.setattr(releases, "default_opener", lambda: github)
    server = build_server(tmp_path / "data" / "stig_kb.sqlite")
    before = _call(server, "defenses_for_technique", {"technique_id": "T1078"})
    assert before["next"][0]["tool"] == "install_knowledge_base"
    installed = _call(server, "install_knowledge_base", {})
    assert installed["status"] == "installed"
    answer = _call(server, "defenses_for_technique", {"technique_id": "T1078"})
    assert answer["technique"]["id"] == "T1078"
    assert answer["sources"]["kb_sha256"] == installed["installed"]["sha256"]["sqlite"]
    assert _call(server, "check_sources", {})["action"] == "none"


def test_build_server__offline_install__never_touches_the_network(tmp_path, kb_path, monkeypatch):
    from stig_mcp.kb import releases  # noqa: PLC0415
    from tests.kb.fake_github import refuse_network  # noqa: PLC0415

    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    monkeypatch.setattr(releases, "default_opener", lambda: refuse_network)
    source = tmp_path / "kb.sqlite.xz"
    source.write_bytes(lzma.compress(kb_path.read_bytes()))
    server = build_server(tmp_path / "data" / "stig_kb.sqlite")
    result = _call(
        server,
        "install_knowledge_base",
        {"path": str(source), "sha256": hashlib.sha256(source.read_bytes()).hexdigest()},
    )
    assert result["status"] == "installed"


def test_build_server__install_refused__surfaces_the_reason_to_the_client(tmp_path, monkeypatch):
    from stig_mcp.kb import releases  # noqa: PLC0415
    from tests.kb.fake_github import FakeGitHub  # noqa: PLC0415

    monkeypatch.setattr(releases, "default_opener", FakeGitHub)
    server = build_server(tmp_path / "data" / "stig_kb.sqlite")
    with pytest.raises(ToolError, match="stig-mcp-fetch"):
        asyncio.run(server.call_tool("install_knowledge_base", {}))


def test_app_module__every_function__is_under_fifty_lines():
    import ast  # noqa: PLC0415
    import inspect  # noqa: PLC0415

    from stig_mcp.server import app as app_module  # noqa: PLC0415

    tree = ast.parse(inspect.getsource(app_module))
    long = {
        n.name: n.end_lineno - n.lineno + 1
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.end_lineno - n.lineno + 1 > 50
    }
    assert long == {}, f"over the 50-line limit: {long}"


def test_build_server__defenses_for_technique_tool__forwards_platforms_and_log_sources(kb_path):
    payload = _call(
        build_server(kb_path),
        "defenses_for_technique",
        {
            "technique_id": "T1078",
            "platforms": ["Windows"],
            "log_sources": ["WinEventLog:Security", "WinEventLog:Sysmon"],
        },
    )
    flagged = {a["id"]: (a["applicable"], a["detectable"]) for a in payload["detect"]["analytics"]}
    assert flagged["AN0001"] == (True, True)


def test_build_server__techniques_for_actor_tool__forwards_platforms_and_log_sources(defenses_kb):
    payload = _call(
        build_server(defenses_kb),
        "techniques_for_actor",
        {"actor": "APT29", "include_defenses": True, "platforms": ["Windows"], "log_sources": ["WinEventLog:Security"]},
    )
    assert payload["summary"]["coverage"]["detectable"] == 1
    assert payload["summary"]["coverage"]["without_applicable_analytic"] == 1
