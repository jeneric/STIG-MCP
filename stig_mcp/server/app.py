import json
import logging
from contextlib import contextmanager
from importlib.metadata import version

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import TextContent

from stig_mcp.ingest import config
from stig_mcp.kb import install
from stig_mcp.kb.db import open_db
from stig_mcp.server import readiness, tools

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """A connection that is opened when there is something to open, and reopened when it
    changes underneath us.

    The server must run with no knowledge base yet, and survive one replaced while it runs, so
    a single connection opened at startup cannot serve.

    A tool call costs one acquire. Almost all of that is readiness.check, which opens the file,
    reads schema_version and closes it again; the os.stat that revalidates identity is
    negligible. The whole acquire is a fraction of a resolve, which is why the ordering is left
    alone.
    """

    def __init__(self, path):
        self._path = path
        self._conn = None
        self._identity = None
        self._sha256 = None
        self._sha256_identity = None

    @property
    def path(self):
        return self._path

    def acquire(self):
        """(conn, None) when answerable, (None, reason) when not."""
        reason = readiness.check(self._path)
        if reason != readiness.READY:
            self._close()
            return None, reason
        current = readiness.identity(self._path)
        if self._conn is None or current != self._identity:
            self._close()
            self._conn = open_db(self._path)
            self._identity = current
        return self._conn, None

    def sha256(self):
        """The installed file's SHA-256, for comparing against a release. Hashing 63 MB costs a
        read of the whole file, so it is cached against the same identity acquire() revalidates."""
        current = readiness.identity(self._path)
        if current is None:
            return None
        if current != self._sha256_identity:
            try:
                self._sha256 = install.file_sha256(self._path)
            except OSError:
                # Removed or made unreadable between the stat above and the read.
                self._sha256, self._sha256_identity = None, None
                return None
            self._sha256_identity = current
        return self._sha256

    def release(self):
        """Close the cached connection so an install can replace the file: Windows refuses to
        replace a file that is open."""
        self._close()

    def _close(self):
        if self._conn is not None:
            self._conn.close()
        self._conn = None
        self._identity = None


@contextmanager
def _guidance_reaches_the_caller():
    """Re-raise tools.CallerError as ToolError, whose message MCPServer forwards. From mcp 2.2 it
    replaces any other exception's message with "Error executing tool ...", and CallerError's
    message tells the caller what to send instead."""
    try:
        yield
    except tools.CallerError as exc:
        raise ToolError(str(exc)) from exc


def _compact(result):
    """One line of JSON, as a content block: MCPServer would indent a dict, adding about 40% and
    pushing summary's CAT I ids past the 500 characters a spilling client previews."""
    return TextContent(type="text", text=json.dumps(result, separators=(",", ":"), ensure_ascii=False))


# Every tool below is `async def` around a synchronous body, and must stay so. MCPServer runs a
# plain `def` tool on a worker thread, while KnowledgeBase caches one sqlite3 connection that
# refuses use from any thread but the one that opened it. An async tool runs on the event loop's
# single thread, so every call reaches that connection from the same thread.
def _register_answer_tools(server, kb):
    @server.tool()
    async def defenses_for_technique(  # noqa: PLR0913
        technique_id: str,
        system_description: str | None = None,
        benchmark_ids: list[str] | None = None,
        severity: list[str] | None = None,
        platforms: list[str] | None = None,
        log_sources: list[str] | None = None,
    ) -> TextContent:
        """Return the defenses the knowledge base holds for an ATT&CK technique: the 800-53r5 controls CTID maps to
        it, the DISA STIG findings that implement those controls on the systems you name, and ATT&CK's own
        mitigations and detection strategy. The answer opens with summary: rules found, rules per CAT,
        control_counts, mitigation and detection counts (detection counts analytics), cat_i (the CAT I V- ids with
        their count), then controls_with_rules. Use those counts rather than counting lists yourself.
        protect.controls maps each control id to its name, family, source and rules. A control's rules include those
        DISA tags to its enhancements (e.g. AC-6(9) under AC-6), since the ATT&CK mapping names base controls; via,
        when present, maps each enhancement to the rules that reach the control only through it. Each finding gives
        its benchmark (stig_id/version, described in resolved_systems), V- id and CAT; titles come with CAT I
        findings, or with every CAT named in severity; when any are missing, summary.titles reads "CAT I only", so
        never name or describe an untitled finding without fetching its title (call again with severity naming its
        CAT); call finding_details with rule ids or V- ids for DISA's check and fix text and the CCIs. severity
        narrows findings to CAT levels, e.g. ["I"]. A technique id ATT&CK has revoked (e.g. T1562) is answered for
        its replacement, and the response reports the redirect in technique.redirected_from. Include the product
        build in system_description where one exists (e.g. 'ESXi 8.0 U3'): some products ship two STIG versions with
        different remediations, and the build selects the one that applies. benchmark_ids narrows to benchmarks you
        already know and accepts at most 200; to scope a system you cannot name, pass system_description instead and
        let the resolver do it. If the knowledge base is not built yet this returns {"status": "not_ready"} with the
        commands to run, rather than an error. platforms names ATT&CK platforms, e.g. ["Windows"], and
        detect.applicable then lists the analytics that apply to them; an unknown name is refused with the full list.
        log_sources names the telemetry you collect, with ATT&CK's log source names, in any case (e.g.
        ["WinEventLog:Security", "WinEventLog:Sysmon"]); log_sources takes up to 100 names. When platforms is given,
        detect.detectable lists (and summary.detection counts) only applicable analytics whose every log source is in
        the list; without platforms, every analytic whose log sources are all collected. detect.analytics maps each
        analytic id to its name and platforms; detect.applicable and detect.detectable list the qualifying ids and
        are present only when platforms or log_sources was given (absent: not judged; empty: none qualify).
        Mitigations are listed by id and name only: call defense_details with M-, DET- or AN- ids for MITRE's text,
        log sources and tunable elements."""
        with _guidance_reaches_the_caller():
            return _compact(
                tools.defenses_for_technique(
                    kb,
                    technique_id,
                    system_description=system_description,
                    benchmark_ids=benchmark_ids,
                    severity=severity,
                    platforms=platforms,
                    log_sources=log_sources,
                )
            )


def _register_actor_tool(server, kb):
    @server.tool()
    async def techniques_for_actor(  # noqa: PLR0913
        actor: str,
        system_description: str | None = None,
        benchmark_ids: list[str] | None = None,
        include_defenses: bool = False,
        severity: list[str] | None = None,
        platforms: list[str] | None = None,
        log_sources: list[str] | None = None,
    ) -> TextContent:
        """List an ATT&CK actor's techniques, optionally expanded with defenses for given systems. actor is an ATT&CK
        group id, name or alias; case, spacing, punctuation and a trailing "Group" or "Team" are ignored, and
        actor.matched_as then names what matched. actor.also_matches, when present, lists other groups the same label
        loosely names. A misspelling is not corrected: the error names the closest groups, so call again with the
        group id of the one meant. The answer opens with summary, which counts the techniques; with include_defenses
        it adds the same counts defenses_for_technique gives, across every technique. Use those counts rather than
        counting lists yourself. controls lists each control once with its rule ids, including rules DISA tags to its
        enhancements, which via names, and findings lists each finding once, without check or fix text (call
        finding_details for those), each naming its benchmark, V- id and CAT, with titles for CAT I or for the CATs
        named in severity; summary.titles reads "CAT I only" when the rest are missing, so fetch a title before naming
        an untitled finding. Each technique lists its control ids grouped by where the mapping came from ("ctid" or
        "override"). benchmark_ids accepts at most 200; it, severity (CAT levels, e.g. ["I"]), platforms and
        log_sources are validated always but only take effect with include_defenses. To scope a system you cannot
        name, pass system_description instead. With include_defenses each technique also lists its ATT&CK mitigations
        (M-ids), its detection strategy (DET-id), analytics (a map of AN-id to platforms, with applicable and
        detectable id lists as in defenses_for_technique), and gaps, the coverage classes the call can judge that
        count that technique as a gap (mitigated_without_rules needs a scoped system, without_applicable_analytic
        platforms, undetectable log_sources), so read gaps rather than deriving them. mitigations maps each M-id to
        its name once, while summary.mitigations counts mitigation references across techniques (one on two techniques
        counts twice). summary.coverage, which comes right after control_counts, counts techniques:
        without_mitigation, mitigated_without_rules (only when a system was scoped; with severity, no rules at the
        requested CAT levels), without_applicable_analytic (only with platforms), detectable and undetectable (only
        with log_sources); summary.detection counts analytics instead. Detection is judged applicability first when
        platforms is given, then detectability over the applicable analytics. Each technique's applicable and
        detectable id lists are judged as in defenses_for_technique, so with platforms detectable is always a subset
        of applicable; log_sources takes up to 100 names. Call defense_details with M-, DET- or AN- ids for MITRE's
        text. If the knowledge base is not built yet this returns {"status": "not_ready"} with the commands to run,
        rather than an error."""
        with _guidance_reaches_the_caller():
            return _compact(
                tools.techniques_for_actor(
                    kb,
                    actor,
                    system_description=system_description,
                    benchmark_ids=benchmark_ids,
                    include_defenses=include_defenses,
                    severity=severity,
                    platforms=platforms,
                    log_sources=log_sources,
                )
            )


def _register_detail_tool(server, kb):
    @server.tool()
    async def finding_details(ids: list[str]) -> TextContent:
        """Return DISA's check and fix text for STIG findings, with each finding's benchmark,
        release and CCIs. ids takes up to 50 rule ids (SV-...r..._rule) or V- ids as listed
        under findings in a defenses_for_technique or techniques_for_actor answer, in any
        case. Prefer the V- id: a rule id carries its release's revision and matches only that
        release. A V- id that two benchmarks or majors share returns every match, each labeled
        with its benchmark. not_found lists ids that matched nothing; if none match, the call
        is refused with an error instead. Quote check_text and fix_text as DISA wrote them, and
        label anything you add, such as commands or explanations, as your own rather than DISA's.
        If the knowledge base is not built yet this returns {"status": "not_ready"} with the
        commands to run, rather than an error."""
        with _guidance_reaches_the_caller():
            return _compact(tools.finding_details(kb, ids))

    @server.tool()
    async def defense_details(ids: list[str], technique_id: str | None = None) -> TextContent:
        """Return MITRE's text for ATT&CK defenses named by id: mitigations (M1026), detection
        strategies (DET0103) and analytics (AN0286), as listed under protect.mitigations and
        detect in a defenses_for_technique answer or under each technique in a
        techniques_for_actor answer. ids takes up to 10 per call, matched case-insensitively. A mitigation returns its
        description and how many techniques it covers; with technique_id it also returns
        MITRE's text about that mitigation on that technique as technique_description, which is
        null when that mitigation is not paired with that technique (a revoked id answers for
        its replacement, reported in technique.redirected_from). A detection strategy returns every
        analytic in full: description, platforms, log_sources (name, channel and data component)
        and mutable_elements, the tunables a detection engineer sets. An analytic id returns
        that analytic alone. Analytics say what to collect, not how to enable it: the enabling
        steps are in the vendor's documentation. not_found lists ids that matched nothing; if
        none match, the call is refused. Quote MITRE's text as written and label anything you
        add as your own. If the knowledge base is not built yet this returns
        {"status": "not_ready"} with the commands to run, rather than an error."""
        with _guidance_reaches_the_caller():
            return _compact(tools.defense_details(kb=kb, ids=ids, technique_id=technique_id))


def _register_resolver_tool(server, kb):
    @server.tool()
    async def resolve_system(system_description: str, limit: int = 5) -> dict:
        """Resolve a free-text system description to candidate DISA STIG(s). Returns
        'candidates' and 'notes'. limit caps the number of distinct benchmarks returned,
        not rows: a benchmark holding more than one STIG major (for example vSphere 8.0)
        contributes every major as its own row, so a caller asking for limit=5 may receive
        more than 5 rows. Include the product build where one exists (e.g. 'ESXi 8.0 U3');
        each candidate reports whether it applies to that build in the 'applicable' field.
        When the description names a product version this knowledge base does not hold, a
        note in 'notes' says so and names the versions it does hold. A description naming
        more than one system is split on 'and' and commas and each part judged separately,
        so it can carry one such note per part, each quoting the part it is about. When more
        benchmarks tie with the last benchmark shown than limit allows, a note in 'notes'
        says how many and suggests calling again with a higher limit.
        If the knowledge base is not built yet this returns {"status": "not_ready"} with the
        commands to run, rather than an error."""
        with _guidance_reaches_the_caller():
            return tools.resolve_system(kb, system_description, limit)


def _register_listing_tools(server, kb):
    # The bare `-> list` below is load bearing; do not parametrize or widen it. In mcp 2.x a bare
    # `list` annotation builds no output schema, so the not_ready dict this tool can return
    # crosses through untouched. `-> list[dict]` makes MCPServer validate the result against that
    # schema and raise ToolError on the dict. `-> list | dict` builds a wrapped output model, so
    # structured_content wraps even the ready-path list in {"result": [...]}, a shape this tool
    # does not return.
    @server.tool()
    async def search_techniques(query: str, limit: int = 10) -> list:
        """Search ATT&CK techniques by name or id. Ids and names ATT&CK has revoked also match,
        returning the replacement technique with redirected_from set to the old id.
        If the knowledge base is not built yet this returns {"status": "not_ready"} with the
        commands to run, rather than an error."""
        with _guidance_reaches_the_caller():
            return tools.search_techniques(kb, query, limit)

    # Same reason as search_techniques above: the bare `-> list` is load bearing.
    @server.tool()
    async def list_stigs(filter: str | None = None) -> list:
        """List the STIGs in the knowledge base, optionally filtered by a substring of the
        title, the benchmark id (e.g. RHEL_9_STIG), or the product keywords.
        If the knowledge base is not built yet this returns {"status": "not_ready"} with the
        commands to run, rather than an error."""
        with _guidance_reaches_the_caller():
            return tools.list_stigs(kb, filter)


def _register_source_tools(server, kb):
    @server.tool()
    async def install_knowledge_base(
        release: str | None = None, path: str | None = None, sha256: str | None = None
    ) -> dict:
        """Install the prebuilt knowledge base this server answers from. With no arguments, download
        the newest release for this server from this project's GitHub releases
        (github.com/jeneric/STIG-MCP), verify its SHA-256 and install it; this downloads and
        verifies about 5 MB and can take several seconds. It is the only tool besides
        check_sources that uses the network. release pins an exact kb-YYYY-MM-DD tag, for
        rollback. On a host without network access, pass path (a .sqlite.xz or .sqlite copied from a
        release) and sha256 (the value its SHA256SUMS lists); nothing is then requested. Call this
        when another tool returns {"status": "not_ready"}, or when check_sources reports "install"."""
        with _guidance_reaches_the_caller():
            return tools.install_knowledge_base(kb, release, path, sha256)

    @server.tool()
    async def check_sources() -> dict:
        """Check whether a newer prebuilt knowledge base is published than the one installed. This
        contacts only this project's GitHub releases (github.com/jeneric/STIG-MCP). action is
        "install" (call install_knowledge_base), "upgrade_package" (a newer knowledge base needs a
        newer stig-mcp; upgrade_to says which), "build_locally" (nothing usable is installed and no
        release exists for this stig-mcp; build with stig-mcp-fetch and stig-mcp-ingest), or
        "none"; reason says why. It works even when the knowledge base is not built, and then
        not_ready says why and what to run."""
        with _guidance_reaches_the_caller():
            return tools.check_sources(kb)


def build_server(kb_path):
    # No startup check of the knowledge base. The server must start without one so its tools can
    # be given something to say about what is missing; every tool consults the holder per call
    # instead. Each registered tool below forwards the holder straight to stig_mcp.server.tools,
    # which checks it first thing and returns a not_ready payload instead of raising when the
    # knowledge base is absent, stale or unreadable.
    kb = KnowledgeBase(kb_path)
    server = MCPServer("stig-mcp", version=version("stig-mcp"))
    _register_answer_tools(server, kb)
    _register_actor_tool(server, kb)
    _register_detail_tool(server, kb)
    _register_resolver_tool(server, kb)
    _register_listing_tools(server, kb)
    _register_source_tools(server, kb)
    return server


def main():
    logging.basicConfig(level=logging.INFO)
    state = readiness.check(config.KB_PATH)
    if state != readiness.READY:
        logger.warning(
            "Knowledge base at %s is not usable yet (%s). The server is starting anyway; "
            "its tools will report what to run.",
            config.KB_PATH,
            state,
        )
    logger.info("Serving stig-mcp from knowledge base %s", config.KB_PATH)
    build_server(config.KB_PATH).run()
