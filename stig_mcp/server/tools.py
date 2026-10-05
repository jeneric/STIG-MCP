import difflib
import re
from collections import Counter

from stig_mcp.kb import freshness, install, queries, releases
from stig_mcp.resolver.resolver import resolve
from stig_mcp.server import readiness


class CallerError(ValueError):
    """The caller's arguments cannot be answered; the message says what to send instead. The MCP
    server forwards this message to the caller, and only this one: any other exception is a bug
    or a broken file, and its text stays in the server log."""


def _answerable(kb):
    """(conn, None) or (None, not_ready payload). One line at the top of every tool."""
    conn, reason = kb.acquire()
    if conn is None:
        return None, readiness.payload(kb.path, reason)
    return conn, None


def _explicit_scope(conn, benchmark_ids):
    """Hydrate caller-supplied benchmark_ids into the shape the resolver returns, one entry
    per KB version of each id. An id the KB does not hold stays in the list with a note:
    dropping it would leave the caller with no findings and nothing to explain them."""
    rows = queries.stigs_by_ids(conn, benchmark_ids)
    # A caller-named id that the KB holds at more than one major returns every version's
    # findings, unfiltered by build, since no description was given to scope by. Flagging
    # that here is the only way the caller learns two majors (possibly with contradictory
    # remediations) are both in the response.
    version_counts = {}
    for row in rows:
        version_counts[row["stig_id"]] = version_counts.get(row["stig_id"], 0) + 1
    resolved = [
        {
            **row,
            "score": 100.0,
            "matched_on": "explicit",
            "high_confidence": True,
            "applicable": True,
            "applicability": "multi-major-explicit" if version_counts[row["stig_id"]] > 1 else None,
            "wanted_version": None,
            "build": None,
            "version_coverage": [],
            "tied_omitted": 0,
        }
        for row in rows
    ]
    known = {row["stig_id"] for row in rows}
    notes = []
    seen_unknown = set()
    for stig_id in benchmark_ids:
        if stig_id in known or stig_id in seen_unknown:
            continue
        seen_unknown.add(stig_id)
        resolved.append(
            {
                "stig_id": stig_id,
                "title": None,
                "version": None,
                "score": 0.0,
                "matched_on": "explicit",
                "high_confidence": False,
                "applicable": True,
                "applicability": None,
                "wanted_version": None,
                "build": None,
                "version_coverage": [],
                "tied_omitted": 0,
            }
        )
        notes.append(
            f"stig_id '{stig_id}' is not in the knowledge base, so it contributes no findings. "
            f"Call list_stigs to see the available benchmark ids."
        )
    return [(row["stig_id"], row["version"]) for row in rows], resolved, notes


def _note_scoped(hit):
    return (
        f"Scoped to {hit['stig_id']} V{hit['version']} for build update {hit['build']}. This "
        f"knowledge base holds one release per major, and a build letter suffix does not change "
        f"which major applies, so verify against the release deployed at your site."
    )


def _note_no_official_stig(hit):
    return (
        f"Build update {hit['build']} of {hit['stig_id']} predates the first official STIG, so no "
        f"STIG steps are returned. The 800-53 controls below still apply. Supply a later build to "
        f"get fix and check steps."
    )


def _note_ambiguous(hit):
    return (
        f"{hit['stig_id']} exists at more than one major in this knowledge base, and their "
        f"remediations differ. Findings from all of them are returned, labeled by stig_version. "
        f"Supply a build in the system description to scope to one."
    )


def _note_ungoverned(hit):
    return (
        f"A product build was recognized in the description, but no applicability rule covers "
        f"{hit['stig_id']}, so it did not affect scoping."
    )


def _note_multi_major_explicit(hit):
    # The ambiguous-no-build note cannot be reused here: it tells the caller to supply a
    # build in system_description, and this path never reads system_description at all.
    return (
        f"{hit['stig_id']} exists at more than one major in this knowledge base, and their "
        f"remediations differ. All are returned, labeled by stig_version. Naming a benchmark id "
        f"returns every version it has; to scope to one, drop benchmark_ids and describe the system "
        f"with its build instead, for example 'ESXi 8.0 U3'."
    )


def _note_superseded(hit):
    # Normally the scoped sibling's note explains a benchmark's choice, and this reason
    # renders nothing so the two do not repeat each other. This fires only when no scoped
    # sibling exists (see _applicability_notes), so it is the only thing left to explain
    # why the benchmark is here with no applicable findings.
    return (
        f"{hit['stig_id']} is only held here at the superseded V{hit['version']}. Build "
        f"update {hit['build']} needs V{hit['wanted_version']}, which this knowledge base "
        f"does not hold, so no STIG steps are returned for {hit['stig_id']}. The 800-53 "
        f"controls below still apply."
    )


_NOTE_BENCHMARK_LIMIT = 4


def _listed(benchmarks):
    """At most four ids, then a count. _applicability_notes caps for the same reason:
    a twelve-component vSphere answer would otherwise be all note and no content."""
    shown = benchmarks[:_NOTE_BENCHMARK_LIMIT]
    remainder = len(benchmarks) - len(shown)
    return ", ".join(shown) + (f" and {remainder} more" if remainder else "")


def _note_version_uncovered(fragment, coverage):
    """Say the version is not held, and which versions are.

    "This knowledge base holds" and never "DISA publishes": a benchmark that exists
    upstream but was not ingested must not be denied.

    Quotes the FRAGMENT it speaks for, not the caller's whole description, which is what
    lets a two-product query carry one of these per product. For a single-fragment query
    that is the description with surrounding whitespace and the split token stripped, so
    '  RHEL 7  ' and 'RHEL 7,' both quote 'RHEL 7'.
    """
    benchmarks = coverage["benchmarks"]
    plural = len(benchmarks) > 1
    return (
        f"This knowledge base holds no STIG for '{fragment}'. The closest "
        f"{'benchmarks are' if plural else 'benchmark is'} {_listed(benchmarks)}, "
        f"covering {', '.join(coverage['covered_versions'])}. "
        f"{'None of them applies' if plural else 'It does not apply'} to that version; "
        f"to use one anyway, pass it in benchmark_ids."
    )


def _note_version_agnostic(fragment, coverage):
    """Explain why naming a version cost the caller their auto-scope.

    Deliberately does not assert that the benchmark covers the named version. Whether
    the Chrome STIG applies to build 120 is a judgment this knowledge base cannot make,
    so the note explains the silence and hands the decision back.
    """
    benchmarks = coverage["benchmarks"]
    plural = len(benchmarks) > 1
    # The version the caller named is deliberately not quoted back. normalize decomposes it
    # into tokens, so 'Google Chrome 120.0.6099' would be echoed as "0, 120, 6099", which
    # reorders the caller's own words. The fragment below carries it verbatim instead.
    #
    # The subject list is capped and the benchmark_ids clause is not: advice a caller cannot paste
    # is worse than a long sentence.
    return (
        f"{_listed(benchmarks)} {'are' if plural else 'is'} not version-specific: this "
        f"knowledge base holds no per-release benchmark for this product. The version you "
        f"named does not appear in {'them' if plural else 'it'}, which is why nothing was "
        f"auto-scoped, and is not evidence that {'they do' if plural else 'it does'} not "
        f"apply to '{fragment}'. Pass benchmark_ids={benchmarks!r} to scope to "
        f"{'them' if plural else 'it'}."
    )


_VERSION_COVERAGE_NOTE = {
    "uncovered": _note_version_uncovered,
    "version-agnostic": _note_version_agnostic,
}


def _version_coverage_notes(hits):
    """One note per fragment that has something to say, in the order the caller wrote them.
    Reads hit zero because the verdicts are query-level and stamped identically on every row.

    Each note quotes its own FRAGMENT rather than the whole description, which is what makes
    more than one of them readable: each explains its own half of a two-product description
    without claiming anything about the other (see resolver._coverage_per_fragment).

    Silent for a fragment that matched something confidently, because the two statements
    contradict each other: an alias makes 'RHEL 8.9' a confident RHEL_8_STIG hit while the
    verdict says the version is not held, and telling a caller both is worse than telling them
    neither.

    The gate reads `fragment_confident`, which resolve() computes from THAT fragment's own
    hits, and not the `high_confidence` on the rows here: a row's flag belongs to whichever
    fragment won it in the merged map (see resolver._coverage_per_fragment). For a
    single-fragment query the two are the same value.

    The difference cuts in BOTH directions. A fragment reaching a benchmark made confident by
    the OTHER fragment still speaks. A fragment that matched confidently on its own stays
    silent even when another fragment's higher-scoring hit cleared its row flag, as in
    'Nokia Service 2 and RHEL 9': 'Nokia Service 2' ALONE confidently scopes
    Nokia_SR_OS_25-x_L2S_STIG and emits no note, and the pair must not contradict what the same
    fragment says by itself.
    """
    # Only the NOTE is gated. The raw verdicts still ship on every candidate row, so a caller
    # reading `version_coverage` directly can see one the prose deliberately withheld.
    return [
        _VERSION_COVERAGE_NOTE[coverage["verdict"]](coverage["fragment"], coverage)
        for coverage in (hits[0]["version_coverage"] if hits else [])
        if not coverage["fragment_confident"]
    ]


def _tied_omitted_note(description, hits):
    """The note for benchmarks the cap cut out of a score tier, or None.

    Reads hit zero because the count is query-level and stamped identically on every row, the
    same way _version_coverage_notes reads its verdicts. Unlike that note this one never
    replaces another: it describes the completeness of the list, not what the list means, so
    it is true alongside whatever else the path has to say.
    """
    omitted = hits[0]["tied_omitted"] if hits else 0
    if not omitted:
        return None
    subject = "benchmark" if omitted == 1 else "benchmarks"
    verb = "was" if omitted == 1 else "were"
    pronoun = "it" if omitted == 1 else "them"
    return (
        f"{omitted} further {subject} scored exactly as well as the last one shown for "
        f"'{description}' and {verb} omitted. Call resolve_system with a higher limit to see "
        f"{pronoun}, or name the product more precisely."
    )


_APPLICABILITY_NOTE = {
    "scoped": _note_scoped,
    "no-official-stig": _note_no_official_stig,
    "ambiguous-no-build": _note_ambiguous,
    "ungoverned-build": _note_ungoverned,
    "multi-major-explicit": _note_multi_major_explicit,
    "superseded-major": _note_superseded,
}


def _applicability_notes(hits):
    """One note per (benchmark, reason). A vSphere query resolves twelve components the
    same way, and twelve identical sentences would bury the rest of the response.

    superseded-major is suppressed when a scoped sibling of the same stig_id is present:
    that sibling's own note already explains the benchmark's choice, and a second note
    would only repeat it. When no scoped sibling made it into `hits`, whether because the
    KB never held it or because scoping truncated it away, this is the only note left to
    explain the benchmark's presence with no applicable findings."""
    scoped_ids = {hit["stig_id"] for hit in hits if hit.get("applicability") == "scoped"}
    seen, notes = set(), []
    for hit in hits:
        reason = hit.get("applicability")
        if reason == "superseded-major" and hit["stig_id"] in scoped_ids:
            continue
        key = (hit["stig_id"], reason)
        if reason not in _APPLICABILITY_NOTE or key in seen:
            continue
        seen.add(key)
        notes.append(_APPLICABILITY_NOTE[reason](hit))
    return notes


# Every named id becomes one bound SQL parameter in stigs_by_ids, and one scope pair per KB
# VERSION of that id, which findings_for_control's outer query binds two parameters for, on
# top of five for the control and its enhancement prefix. The library currently ships at most
# 2 majors of any id (the deliberate vSphere dual-major families), and nothing enforces that
# bound, so 200 ids is at most 400 pairs and 805 parameters, 808 with a severity filter, under
# the 999 that SQLite below 3.32 defaults to.
# Raise the cap, or see a third major ship, and that arithmetic has to be redone, not just the
# constant.
#
# 200 is also far past any real call: a caller naming benchmarks by hand is narrowing a scope,
# not enumerating the corpus.
#
# **This bounds BOUND PARAMETERS, not response size, and those diverge hard.** techniques_for_actor
# with include_defenses at 200 ids can still return a very large answer. That is legal, but
# do not read 200 as a safety margin for the caller. A response-size guard would be a separate
# rule, measured in bytes.
_MAX_BENCHMARK_IDS = 200


def _check_benchmark_ids(benchmark_ids):
    """Reject a benchmark_ids list too long to be a scope, at the tools that ACCEPT it.

    Called from each public tool rather than from _resolve_scope, because
    `techniques_for_actor` accepts benchmark_ids and only forwards it when include_defenses is
    set: checking at the choke point would let a caller pass thousands of ids to that tool and
    be told nothing. One helper, two call sites, so the rule is still written once.
    """
    if benchmark_ids and len(benchmark_ids) > _MAX_BENCHMARK_IDS:
        raise CallerError(
            f"benchmark_ids names {len(benchmark_ids)} benchmarks, over the limit of {_MAX_BENCHMARK_IDS}. "
            f"A list this long is not a scope: benchmark_ids exists to narrow the answer to "
            f"benchmarks you already know apply. Pass the handful that describe the system. "
            f"If you genuinely need more, split them across calls of at most {_MAX_BENCHMARK_IDS} "
            f"and merge the results, which returns the same findings as one call would. "
            f"Passing system_description instead scopes a system you cannot name, but it "
            f"resolves only the best few matches rather than a broad list. Call list_stigs "
            f"with a filter substring to see the ids on hand."
        )


_CATS = ("I", "II", "III")


def _check_severity(severity):
    if severity is None:
        return None
    # A bare string would iterate by character, so "II" would read as CAT I.
    valid = isinstance(severity, list | tuple) and severity and all(cat in _CATS for cat in severity)
    if not valid:
        raise CallerError(
            f"severity must list CAT values drawn from 'I', 'II' and 'III', for example ['I'] for "
            f"CAT I only or ['I', 'II'] for CAT I and II; got {severity!r}. Omit it for every level."
        )
    return tuple(dict.fromkeys(severity))


_MAX_FINDING_IDS = 50


def _check_finding_ids(ids):
    if not ids:
        raise CallerError(
            "ids must name at least one finding: a rule id (SV-...r..._rule) or V- id from the "
            "findings of a defenses_for_technique or techniques_for_actor answer."
        )
    if len(ids) > _MAX_FINDING_IDS:
        raise CallerError(
            f"ids names {len(ids)} findings, over the limit of {_MAX_FINDING_IDS}. Split them across "
            f"calls of at most {_MAX_FINDING_IDS}."
        )


_MAX_LOG_SOURCES = 100


def _check_list(name, value):
    """A bare string would iterate by character, as _check_severity guards against."""
    if value is None:
        return None
    if not isinstance(value, list | tuple) or not value or not all(isinstance(item, str) for item in value):
        example = {"platforms": "['Windows']", "log_sources": "['WinEventLog:Security']"}[name]
        raise CallerError(
            f"{name} must be a non-empty list of names, for example {name}={example}; got {value!r}. "
            f"Omit it to leave the answer unfiltered."
        )
    return tuple(dict.fromkeys(item.strip() for item in value))


def _check_platforms(conn, platforms):
    wanted = _check_list("platforms", platforms)
    if wanted is None:
        return None
    known = queries.platform_names(conn)
    spellings = _spellings_by_key(known)
    unknown = [platform for platform in wanted if platform.casefold() not in spellings]
    if unknown:
        raise CallerError(
            f"platforms names {', '.join(repr(p) for p in unknown)}, which ATT&CK does not use. "
            f"Pass names from this list, in any case: {', '.join(known)}."
        )
    return list(dict.fromkeys(spellings[platform.casefold()][0] for platform in wanted))


def _check_log_sources(conn, log_sources):
    wanted = _check_list("log_sources", log_sources)
    if wanted is None:
        return None
    if len(wanted) > _MAX_LOG_SOURCES:
        raise CallerError(
            f"log_sources names {len(wanted)} sources, over the limit of {_MAX_LOG_SOURCES}. Pass the "
            f"sources your telemetry actually collects; a list this long is not a telemetry inventory."
        )
    known = queries.log_source_names(conn)
    spellings = _spellings_by_key(known)
    unknown = [source for source in wanted if source.casefold() not in spellings]
    if unknown:
        hints = []
        for source in unknown:
            closest = _closest(source, spellings)
            hints.append(f"'{source}' (closest: {', '.join(closest)})")
        raise CallerError(
            f"log_sources names sources ATT&CK does not use: {'; '.join(hints)}. Pass ATT&CK's log "
            f"source names as defense_details lists them under log_sources; case is ignored."
        )
    return list(dict.fromkeys(name for source in wanted for name in spellings[source.casefold()]))


def _spellings_by_key(names):
    """ATT&CK spells some names two ways (macos:unifiedlog, macOS:unifiedlog), so a caller's
    name stands for every stored spelling that differs from it only in case."""
    spellings = {}
    for name in names:
        spellings.setdefault(name.casefold(), []).append(name)
    return spellings


_WORD_BREAK = re.compile(r"[^0-9a-z]+")


def _words(name):
    return {word for word in _WORD_BREAK.split(name.casefold()) if word}


def _closest(asked, spellings, n=3):
    """The n names nearest `asked`, one spelling each. Names sharing the caller's rarest known
    word come first, so 'WinEventLog:Microsoft-Windows-Sysmon/Operational' leads with
    WinEventLog:Sysmon rather than the names it shares 'Microsoft-Windows' with."""
    names = [variants[0] for variants in spellings.values()]
    word_counts = Counter(word for name in names for word in _words(name))

    def similarity(name):
        return difflib.SequenceMatcher(None, asked.casefold(), name.casefold()).ratio()

    shared = [word for word in _words(asked) if word in word_counts]
    first = []
    if shared:
        rarest = min(shared, key=lambda word: (word_counts[word], word))
        first = sorted((name for name in names if rarest in _words(name)), key=similarity, reverse=True)[:n]
    rest = sorted((name for name in names if name not in first), key=similarity, reverse=True)
    return (first + rest)[:n]


def _resolve_scope(conn, system_description, benchmark_ids):
    if benchmark_ids:
        # _explicit_scope only ever returns notes about unknown ids; the multi-major-explicit
        # note it never renders is added here, alongside the other applicability notes, so
        # every path through _resolve_scope emits one note per (benchmark, reason).
        scope, resolved, notes = _explicit_scope(conn, benchmark_ids)
        notes = [*notes, *_applicability_notes(resolved)]
        # benchmark_ids bypasses the resolver entirely, so system_description (if also given)
        # is never read. The multi-major-explicit note tells the caller to describe the
        # system instead, with an example that can read back the caller's own input
        # verbatim if they already passed one; without this, nothing says it was ignored.
        if system_description and any(r.get("applicability") == "multi-major-explicit" for r in resolved):
            notes.append(
                f"system_description ('{system_description}') was supplied but ignored: benchmark_ids "
                f"bypasses the resolver entirely. Drop benchmark_ids to scope from the description instead."
            )
        return scope, resolved, notes
    if system_description:
        hits = resolve(conn, system_description)
        # Both sub-branches carry it. On the confident path this is not merely informational:
        # high_confidence is filtered out of an ALREADY CAPPED list, so a cut inside a tier can
        # drop a confident benchmark out of the scope itself.
        omitted = _tied_omitted_note(system_description, hits)
        omitted_notes = [omitted] if omitted else []
        confident = [h for h in hits if h["high_confidence"]]
        if confident:
            scope = [(h["stig_id"], h["version"]) for h in confident if h["applicable"]]
            # Version notes JOIN the applicability prose here rather than replacing it, which is
            # the opposite of what they do on the unconfident branch below, and the asymmetry is
            # the point. There, the two sentences describe the same failure and the specific one
            # supersedes the generic. Here they describe DIFFERENT fragments: when one product is
            # scoped confidently, the other half of the description still deserves the sentence it
            # would get alone (see resolver._coverage_per_fragment); suppressing it would leave the
            # remediation path silent about half of what the caller named.
            #
            # Safe on a single-fragment query by construction, not by luck: the only fragment
            # there is the one that matched confidently, so _version_coverage_notes' gate
            # suppresses it.
            #
            # Passed the full `hits` rather than `confident`, which reads oddly beside the
            # scope built from `confident` just above. The gate gets its confidence from the
            # verdict, not from these rows, so the two arguments are interchangeable and
            # passing the filtered one would imply a distinction that does not exist.
            return (
                scope,
                confident,
                [
                    *_applicability_notes(confident),
                    *_version_coverage_notes(hits),
                    *omitted_notes,
                ],
            )
        # No applicability notes: nothing was scoped, so any "Scoped to ..." note would be false.
        # A version-coverage note replaces the generic one rather than joining it: once the
        # version is known to be missing, saying so beats sending the caller to browse candidates.
        specific = _version_coverage_notes(hits)
        # Two different truths. With candidates, the caller can go look at them. With none, sending
        # them to resolve_system is a dead end: it runs this same resolver and will return the same
        # nothing. A query naming a product the corpus lacks collects no coincidental version
        # matches, so 'our Sharepont 2016 farm' finds nothing at all.
        if hits:
            fallback = (
                f"No STIG confidently matched '{system_description}'. Call resolve_system "
                f"or list_stigs to see candidates, or pass benchmark_ids explicitly."
            )
        else:
            fallback = (
                f"Nothing in this knowledge base resembles '{system_description}', so there are no "
                f"candidates to browse. Check the spelling, name the product as DISA does, or call "
                f"list_stigs to see what is held."
            )
        return [], hits, [*(specific or [fallback]), *omitted_notes]
    return (
        [],
        [],
        [
            "No system supplied: returning controls without STIG steps. "
            "Provide system_description or benchmark_ids to get fix/check steps."
        ],
    )


def _technique_or_redirect(conn, technique_id):
    """The technique to answer for, plus any note explaining a redirect. A revoked id
    answers for its replacement instead of failing, since the caller usually got the old
    id from a report and cannot tell it was renumbered."""
    technique = queries.technique_row(conn, technique_id)
    if technique is not None:
        return {**technique, "redirected_from": None}, []
    moved = queries.revocation(conn, technique_id)
    if moved is None:
        raise CallerError(
            f"Unknown technique_id '{technique_id}'. Call search_techniques to find a valid ATT&CK "
            f"technique id (e.g. 'T1078')."
        )
    replacement = queries.technique_row(conn, moved["replacement_id"])
    note = (
        f"ATT&CK revoked {technique_id} ({moved['revoked_name']}) in favor of "
        f"{moved['replacement_id']}. Answering for {moved['replacement_id']}; cite that id instead."
    )
    return {**replacement, "redirected_from": technique_id}, [note]


def _sources_block(conn):
    """What this answer was built from, so a reader can verify it against DISA, NIST and
    MITRE directly. Every value is read from ingest_meta."""
    meta = queries.source_versions(conn)
    block = {}
    for key, name in (
        ("stig_library", "stig_library"),
        ("attack", "attack"),
        ("ctid", "ctid"),
        ("ctid_attack_version", "ctid_attack_version"),
        ("catalog", "control_catalog"),
        ("cci", "cci_list"),
    ):
        entry = meta.get(key)
        if entry is None:
            continue
        value = entry["artifact"] if key in ("stig_library", "cci") else entry["version"]
        # A present-but-empty value (the repo fixture oscal_catalog.json carries no
        # metadata.version, for one) asserts nothing and is worse than an absent key in a
        # block meant for verification: skip it the same way a missing row already is,
        # rather than citing an empty string.
        if not value:
            continue
        block[name] = value
    ingested = next((e["ingested_at"] for e in meta.values() if e["ingested_at"]), None)
    if ingested:
        block["ingested_at"] = ingested
    return block


def _currency_note(row, library_artifact, library_populated):
    """One note per benchmark that is not current library guidance, stating the
    verifiable reason rather than a guess.

    Nothing inside an XCCDF distinguishes retired from current except the deprecated
    status, which DISA sets only on a final release, so absence of it proves nothing.
    Absence from the library is a fact only when a library was present and actually
    contributed benchmarks; a compilation that classified correctly but yielded none
    (truncated download, holds only SRGs) leaves the meta row in place with nothing
    to compare against, so that case declines exactly like having no compilation at all,
    but names the compilation so the operator learns it, not the benchmark, is the
    problem."""
    label = f"{row['stig_id']} {row.get('release_label') or ''}".strip()
    if row.get("xccdf_status") == "deprecated":
        return f"DISA marked {label} deprecated on {row.get('xccdf_status_date')}."
    if library_artifact is None:
        return (
            "This knowledge base was built without a library compilation, so whether "
            f"{label} is current guidance cannot be determined."
        )
    if not library_populated:
        return (
            f"{library_artifact} was present at build time but contributed no benchmarks, so "
            f"whether {label} is current guidance cannot be determined."
        )
    if row.get("origin") == "sunset":
        return f"{label} came from a sunset compilation and is not in {library_artifact}."
    return (
        f"{label} ({row.get('release_info')}) was supplied as a local artifact and is not in "
        f"{library_artifact}. It may be newer than that compilation or retained from an earlier one."
    )


def _mapping_meta(conn):
    """The three versions needed to judge a missing mapping: the technique data's own ATT&CK
    version, the ATT&CK version CTID mapped against, and that mapping's release date."""
    meta = queries.source_versions(conn)
    return {
        "attack": (meta.get("attack") or {}).get("version") or None,
        "ctid_attack": (meta.get("ctid_attack_version") or {}).get("version") or None,
        "ctid_release": (meta.get("ctid_attack_release") or {}).get("version") or None,
    }


def _no_controls_note(technique_id, coverage, mapping):
    """Why a technique has no controls, in the one of five forms its data supports. Only the
    uncovered case suggests overrides.yaml, because only there is an operator mapping the fix."""
    status = coverage["ctid_status"]
    if status == "mapped":
        return f"All CTID-mapped controls for {technique_id} are suppressed in overrides.yaml."
    if status == "non_mappable":
        return f"CTID reviewed {technique_id} and found no 800-53r5 control that mitigates it."
    created, released, version = coverage["created"], mapping["ctid_release"], mapping["ctid_attack"] or "unknown"
    if created and released and created > released:
        return (
            f"{technique_id} was added to ATT&CK on {created}, after ATT&CK {version} ({released}), "
            f"which the CTID mapping covers."
        )
    if created and released:
        return f"The CTID mapping does not cover {technique_id}. Add a mapping in overrides.yaml if this is a gap."
    return (
        f"{technique_id} is not in the CTID mapping file (ATT&CK {version}); provide attack_index.json to "
        f"tell a newer technique from an uncovered one."
    )


def _version_gap_note(mapping):
    """When technique data and the CTID mapping come from different ATT&CK versions, name
    both so a reader knows the mapping may lag."""
    attack, ctid = mapping["attack"], mapping["ctid_attack"]
    if attack and ctid and attack != ctid:
        return f"Controls come from the CTID mapping for ATT&CK {ctid}; technique data is ATT&CK {attack}."
    return None


def _provenance_notes(conn, resolved_systems):
    meta = queries.source_versions(conn)
    library_artifact = (meta.get("stig_library") or {}).get("artifact")
    library_populated = library_artifact is not None and queries.library_populated(conn)
    notes = []
    for row in resolved_systems:
        if row.get("origin") == "library" and row.get("xccdf_status") != "deprecated":
            continue
        if row.get("version") is None:
            continue  # an unknown stig_id already has its own note
        notes.append(_currency_note(row, library_artifact, library_populated))
    return notes


def _defense_counts(mitigations, detection, platforms, log_sources):
    analytics = detection["analytics"] if detection else []
    counts = {"analytics": len(analytics)}
    if platforms:
        counts["applicable"] = sum(1 for a in analytics if a["applicable"])
    if log_sources:
        counts["detectable"] = sum(1 for a in analytics if a["detectable"])
    return {"mitigations": len(mitigations), "detection": counts}


def _with_catalog(rows):
    return [{**row, "catalog": "disa"} for row in rows]


def defenses_for_technique(  # noqa: PLR0913
    kb, technique_id, system_description=None, benchmark_ids=None, severity=None, platforms=None, log_sources=None
):
    conn, not_ready = _answerable(kb)
    if not_ready:
        return not_ready
    _check_benchmark_ids(benchmark_ids)
    severities = _check_severity(severity)
    platforms = _check_platforms(conn, platforms)
    log_sources = _check_log_sources(conn, log_sources)
    technique, notes = _technique_or_redirect(conn, technique_id)
    scope, resolved_systems, scope_notes = _scope_context(conn, system_description, benchmark_ids)
    findings = {}
    controls, technique_notes = _technique_controls(
        conn, technique["id"], _ControlFindings(conn, scope, severities), findings
    )
    if scope:
        technique_notes += [_no_rules_note([c["control_id"]], severities) for c in controls if not c["rules"]]
    findings = _cat_ordered(findings)
    mitigations = queries.mitigations_for_technique(conn, technique["id"])
    detection = queries.detection_for_technique(conn, technique["id"], platforms, log_sources)
    counts = _defense_counts(mitigations, detection, platforms, log_sources)
    return {
        "summary": _summary(findings, {c["control_id"]: c["rules"] for c in controls}, counts),
        "technique": technique,
        "resolved_systems": _with_catalog(resolved_systems),
        "protect": {"controls": controls, "findings": _listed_findings(findings), "mitigations": mitigations},
        "detect": detection,
        "notes": notes + scope_notes + technique_notes,
        "sources": {**_sources_block(conn), "kb_sha256": kb.sha256()},
    }


def _scope_context(conn, system_description, benchmark_ids):
    """The scope and the notes that hold for every technique answered against it."""
    scope, resolved_systems, notes = _resolve_scope(conn, system_description, benchmark_ids)
    notes += _provenance_notes(conn, resolved_systems)
    gap = _version_gap_note(_mapping_meta(conn))
    if gap:
        notes.append(gap)
    return scope, resolved_systems, notes


class _ControlFindings:
    """Each control's findings in one scope, queried once however many techniques share it."""

    def __init__(self, conn, scope, severities):
        self.conn, self.scope, self.severities = conn, scope, severities
        self._rows = {}

    def rows(self, control_id):
        if control_id not in self._rows:
            self._rows[control_id] = queries.findings_for_control(self.conn, control_id, self.scope, self.severities)
        return self._rows[control_id]


def _enhancement_number(control_id):
    """So AC-2(3) sorts before AC-2(10), which a string sort reverses."""
    return int(control_id[control_id.index("(") + 1 : -1])


def _technique_controls(conn, technique_id, control_findings, findings):
    """One technique's controls and its own notes; adds each finding to `findings`."""
    controls = queries.effective_controls(conn, technique_id)
    notes = []
    if not controls:
        notes.append(
            _no_controls_note(technique_id, queries.technique_coverage(conn, technique_id), _mapping_meta(conn))
        )
    listed = []
    for control in controls:
        control_id = control["control_id"]
        rows = control_findings.rows(control_id)
        via = {}
        for row in rows:
            findings.setdefault(row["rule_id"], {key: value for key, value in row.items() if key != "via"})
            for enhancement in row["via"]:
                via.setdefault(enhancement, []).append(row["rule_id"])
        entry = {
            "control_id": control_id,
            "name": control["name"],
            "family": control["family"],
            "source": [control["source"]],
            "rules": [row["rule_id"] for row in rows],
        }
        if via:
            entry["via"] = {key: via[key] for key in sorted(via, key=_enhancement_number)}
        listed.append(entry)
    return listed, notes


def _no_rules_note(control_ids, severities):
    levels = " or ".join(f"CAT {cat}" for cat in severities) + " " if severities else ""
    if len(control_ids) == 1:
        return (
            f"Control {control_ids[0]} has no {levels}rules, at the control or any of its enhancements, "
            f"in the resolved STIG(s)."
        )
    return (
        f"{len(control_ids)} controls have no {levels}rules, at the control or any of their enhancements, "
        f"in the resolved STIG(s): {', '.join(control_ids)}."
    )


def _cat_ordered(findings):
    # An unknown CAT ranks with III, as _CAT_ORDER ranks it in SQL.
    rank = {cat: position for position, cat in enumerate(_CATS)}
    ordered = sorted(
        findings.values(),
        key=lambda f: (rank.get(f["severity"]["cat"], rank["III"]), f["stig_id"], f["stig_version"], f["rule_id"]),
    )
    return {f["rule_id"]: f for f in ordered}


def _benchmark_key(row):
    return f"{row['stig_id']}/{row['stig_version']}"


def _listed_findings(findings):
    """List-answer entries: the rule id is the key, resolved_systems describes the benchmark,
    the CAT fixes the level, and CCIs stay in finding_details."""
    return {
        rule_id: {
            "benchmark": _benchmark_key(finding),
            "group_id": finding["group_id"],
            "severity": finding["severity"]["cat"],
            "title": finding["title"],
        }
        for rule_id, finding in findings.items()
    }


def _summary(findings, rules_by_control, defense_counts=None):
    """Counts and the CAT I ids, first in the answer: a client that spills a large result to a
    file shows the model only its opening characters. Stating the counts also spares the model
    counting long lists itself, which it gets wrong."""
    by_cat = {}
    for finding in findings.values():
        by_cat[finding["severity"]["cat"]] = by_cat.get(finding["severity"]["cat"], 0) + 1
    # by_cat counts rules, and a requirement held at two majors is one V- id but two rules, so
    # cat_i carries its own count for the reader to check the listed ids against.
    cat_i_findings = (f for f in findings.values() if f["severity"]["cat"] == "I")
    cat_i = list(dict.fromkeys(f["group_id"] or f["rule_id"] for f in cat_i_findings))
    with_rules = [control_id for control_id, rules in rules_by_control.items() if rules]
    # The control id list goes last, since a long one would push the CAT I ids out of that
    # opening.
    return {
        "findings": len(findings),
        "by_cat": by_cat,
        "control_counts": {"mapped": len(rules_by_control), "with_rules": len(with_rules)},
        # Every count goes before cat_i, whose id list can run past a client's preview.
        **(defense_counts or {}),
        "cat_i": {"count": len(cat_i), "ids": cat_i},
        "controls_with_rules": with_rules,
    }


def _unresolved_actor(actor, match):
    retry = "Call again with the group id of the one you mean."
    if match.groups:
        named = ", ".join(f"{group['name']} ({group['id']})" for group in match.groups)
        return f"Actor '{actor}' names more than one ATT&CK group: {named}. {retry}"
    if match.suggestions:
        closest = ", ".join(
            f"{s['name']} ({s['id']})" if s["via"] is None else f"{s['name']} ({s['id']}, as '{s['via']}')"
            for s in match.suggestions
        )
        return f"Unknown actor '{actor}'. Closest ATT&CK groups: {closest}. {retry}"
    return f"Unknown actor '{actor}'. Provide an ATT&CK group id (e.g. 'G0016') or a known name/alias."


def _detect_class(detection, platforms, log_sources):
    """Which Detect count a technique lands in, or None when neither filter was given. The
    order is the partition: applicability is judged before detectability."""
    analytics = detection["analytics"] if detection else []
    if platforms:
        analytics = [a for a in analytics if a["applicable"]]
        if not analytics:
            return "without_applicable_analytic"
    if log_sources:
        return "detectable" if any(a["detectable"] for a in analytics) else "undetectable"
    return None


def _gaps(technique, has_rules, scoped, detect_class):
    """The coverage keys that count this technique as a gap, in coverage's order."""
    gaps = []
    if not technique["mitigations"]:
        gaps.append("without_mitigation")
    elif scoped and not has_rules:
        gaps.append("mitigated_without_rules")
    if detect_class in ("without_applicable_analytic", "undetectable"):
        gaps.append(detect_class)
    return gaps


def _coverage(rows, scoped, platforms, log_sources):
    """rows: (technique_dict, detect_class) per technique, each technique carrying its gaps."""
    gaps = [gap for technique, _ in rows for gap in technique["gaps"]]
    coverage = {"techniques": len(rows), "without_mitigation": gaps.count("without_mitigation")}
    if scoped:
        coverage["mitigated_without_rules"] = gaps.count("mitigated_without_rules")
    if platforms:
        coverage["without_applicable_analytic"] = gaps.count("without_applicable_analytic")
    if log_sources:
        coverage["detectable"] = [detect_class for _, detect_class in rows].count("detectable")
        coverage["undetectable"] = gaps.count("undetectable")
    return coverage


def _attach_defenses(conn, technique, platforms, log_sources, mitigation_names):
    """Adds the id-only defense fields to one technique; returns its detection block."""
    mitigations = queries.mitigations_for_technique(conn, technique["technique_id"])
    for mitigation in mitigations:
        mitigation_names.setdefault(mitigation["id"], {"name": mitigation["name"]})
    technique["mitigations"] = [m["id"] for m in mitigations]
    detection = queries.detection_for_technique(conn, technique["technique_id"], platforms, log_sources)
    technique["detection_strategy"] = detection["detection_strategy"]["id"] if detection else None
    technique["analytics"] = [
        {key: analytic[key] for key in ("id", "platforms", "applicable", "detectable")}
        for analytic in (detection["analytics"] if detection else [])
    ]
    return detection


def _actor_defense_summary(rows, detections, scoped, platforms, log_sources):
    totals = _defense_counts(
        [m for technique, _ in rows for m in technique["mitigations"]],
        {"analytics": [a for d in detections if d for a in d["analytics"]]},
        platforms,
        log_sources,
    )
    return {"coverage": _coverage(rows, scoped, platforms, log_sources), **totals}


def _attach_controls(conn, technique, control_findings, findings, controls):
    """Adds notes and controls to one technique; returns whether any control has rules."""
    listed, technique["notes"] = _technique_controls(conn, technique["technique_id"], control_findings, findings)
    # Source belongs to the technique-control pair; name, family and rules to the control.
    technique["controls"] = {}
    for control in listed:
        for source in control["source"]:
            technique["controls"].setdefault(source, []).append(control["control_id"])
        controls.setdefault(
            control["control_id"], {k: control[k] for k in ("name", "family", "rules", "via") if k in control}
        )
    return any(control["rules"] for control in listed)


def _expand_techniques(conn, techniques, control_findings, collected, filters):
    """Attaches controls, defenses and gaps to each technique, filling the shared findings,
    controls and mitigation-name maps; returns (technique, detect_class) rows and detections."""
    findings, controls, mitigation_names = collected
    scoped, platforms, log_sources = filters
    rows, detections = [], []
    for technique in techniques:
        has_rules = _attach_controls(conn, technique, control_findings, findings, controls)
        detection = _attach_defenses(conn, technique, platforms, log_sources, mitigation_names)
        detect_class = _detect_class(detection, platforms, log_sources)
        technique["gaps"] = _gaps(technique, has_rules, scoped, detect_class)
        rows.append((technique, detect_class))
        detections.append(detection)
    return rows, detections


def _resolved_actor(conn, actor):
    match = queries.resolve_actor(conn, actor)
    if len(match.groups) != 1:
        raise CallerError(_unresolved_actor(actor, match))
    resolved = match.groups[0]
    if match.matched_as is not None:
        resolved["matched_as"] = match.matched_as
    if match.also_matches:
        resolved["also_matches"] = match.also_matches
    return resolved


def techniques_for_actor(  # noqa: PLR0913
    kb,
    actor,
    system_description=None,
    benchmark_ids=None,
    include_defenses=False,
    severity=None,
    platforms=None,
    log_sources=None,
):
    """summary.mitigations counts mitigation references across techniques: a technique with two
    mitigations counts two."""
    conn, not_ready = _answerable(kb)
    if not_ready:
        return not_ready
    _check_benchmark_ids(benchmark_ids)
    severities = _check_severity(severity)
    platforms = _check_platforms(conn, platforms)
    log_sources = _check_log_sources(conn, log_sources)
    resolved = _resolved_actor(conn, actor)
    techniques = queries.techniques_for_actor(conn, resolved["id"])
    sources = {**_sources_block(conn), "kb_sha256": kb.sha256()}
    if not include_defenses:
        return {
            "summary": {"techniques": len(techniques)},
            "actor": resolved,
            "techniques": techniques,
            "sources": sources,
        }
    scope, resolved_systems, notes = _scope_context(conn, system_description, benchmark_ids)
    filters = (bool(scope), platforms, log_sources)
    findings, controls, mitigation_names = {}, {}, {}
    rows, detections = _expand_techniques(
        conn, techniques, _ControlFindings(conn, scope, severities), (findings, controls, mitigation_names), filters
    )
    empty = sorted(control_id for control_id, control in controls.items() if not control["rules"])
    if scope and empty:
        notes.append(_no_rules_note(empty, severities))
    findings = _cat_ordered(findings)
    defense_counts = _actor_defense_summary(rows, detections, *filters)
    return {
        "summary": {
            "techniques": len(techniques),
            **_summary(
                findings,
                {control_id: control["rules"] for control_id, control in controls.items()},
                defense_counts,
            ),
        },
        "actor": resolved,
        "resolved_systems": _with_catalog(resolved_systems),
        "techniques": techniques,
        "controls": controls,
        "findings": _listed_findings(findings),
        "mitigations": dict(sorted(mitigation_names.items())),
        "notes": notes,
        "sources": sources,
    }


def finding_details(kb, ids):
    conn, not_ready = _answerable(kb)
    if not_ready:
        return not_ready
    _check_finding_ids(ids)
    rows = queries.finding_details(conn, ids)
    matched = {row["rule_id"].upper() for row in rows} | {row["group_id"].upper() for row in rows if row["group_id"]}
    not_found = [finding_id for finding_id in ids if finding_id.strip().upper() not in matched]
    if not rows:
        named = ", ".join(f"'{finding_id}'" for finding_id in ids)
        raise CallerError(
            f"No finding in this knowledge base has the id {named}. Pass a rule id "
            f"(SV-...r..._rule) or V- id exactly as a defenses_for_technique or "
            f"techniques_for_actor answer lists it under findings."
        )
    return {"findings": rows, "not_found": not_found, "sources": {**_sources_block(conn), "kb_sha256": kb.sha256()}}


_MAX_DEFENSE_IDS = 10


def _check_defense_ids(ids):
    if not ids:
        raise CallerError(
            "ids must name at least one defense: an M- (mitigation), DET- (detection strategy) or AN- "
            "(analytic) id as a defenses_for_technique or techniques_for_actor answer lists them."
        )
    if len(ids) > _MAX_DEFENSE_IDS:
        raise CallerError(
            f"ids names {len(ids)} defenses, over the limit of {_MAX_DEFENSE_IDS}. A detection strategy "
            f"expands to every analytic with its log sources and tunables, so split them across calls of "
            f"at most {_MAX_DEFENSE_IDS}."
        )


def defense_details(kb, ids, technique_id=None):
    conn, not_ready = _answerable(kb)
    if not_ready:
        return not_ready
    _check_defense_ids(ids)
    technique, notes = (None, [])
    if technique_id is not None:
        technique, notes = _technique_or_redirect(conn, technique_id)
    details = queries.defense_details(conn, ids, technique["id"] if technique else None)
    matched = {item["id"] for group in details.values() for item in group}
    not_found = [defense_id for defense_id in ids if defense_id.strip().upper() not in matched]
    if not matched:
        named = ", ".join(f"'{defense_id}'" for defense_id in ids)
        raise CallerError(
            f"No mitigation, detection strategy or analytic in this knowledge base has the id {named}. "
            f"Pass M-, DET- or AN- ids exactly as a defenses_for_technique or techniques_for_actor answer "
            f"lists them."
        )
    return {
        **details,
        "not_found": not_found,
        "technique": technique,
        "notes": notes,
        "sources": {**_sources_block(conn), "kb_sha256": kb.sha256()},
    }


def resolve_system(kb, system_description, limit=5):
    """Candidates plus any notes explaining them. The shape is a dict, not a bare list,
    because the generic no-match note tells callers to come here for candidates, so this
    is where an explanation has to be able to live."""
    conn, not_ready = _answerable(kb)
    if not_ready:
        return not_ready
    hits = resolve(conn, system_description, limit)
    notes = [
        *_version_coverage_notes(hits),
        *(note for note in (_tied_omitted_note(system_description, hits),) if note),
    ]
    return {"candidates": hits, "notes": notes}


def search_techniques(kb, query, limit=10):
    """Search ATT&CK techniques by name or id. Returns a list of matches, or, when the
    knowledge base is not built yet, a {"status": "not_ready"} dict instead: the return
    type is list | dict."""
    conn, not_ready = _answerable(kb)
    if not_ready:
        return not_ready
    return queries.search_techniques(conn, query, limit)


def list_stigs(kb, filter=None):
    """List the STIGs in the knowledge base. Returns a list of STIGs, or, when the
    knowledge base is not built yet, a {"status": "not_ready"} dict instead: the return
    type is list | dict."""
    conn, not_ready = _answerable(kb)
    if not_ready:
        return not_ready
    return queries.list_stigs(conn, filter)


def install_knowledge_base(kb, release=None, path=None, sha256=None, opener=None):
    """Install from this project's releases, or from a local file when path is given."""
    if path is not None and release is not None:
        raise CallerError(
            "Pass either release (to download that release) or path and sha256 (to install a local file), not both."
        )
    if (path is None) != (sha256 is None):
        raise CallerError(
            "path and sha256 go together: pass the local .sqlite.xz and the SHA-256 its release's "
            "SHA256SUMS lists for it."
        )
    try:
        if path is not None:
            result = install.install_file(path, sha256, kb.path, before_replace=kb.release)
        else:
            result = install.install_release(kb.path, release=release, opener=opener, before_replace=kb.release)
    except install.UnverifiedSource as exc:
        raise CallerError(exc.summary) from exc
    except (install.InstallError, releases.ReleaseError) as exc:
        raise CallerError(str(exc)) from exc
    return {"status": "installed", **result}


def check_sources(kb, opener=None):
    """Whether a newer knowledge base is published in this project's releases than the one
    installed. Answers even when the knowledge base is not built, carrying the same not_ready
    payload every other tool returns then. Operators who build locally compare against MITRE,
    CTID, NIST and DISA directly with stig-mcp-fetch --check."""
    conn, not_ready = _answerable(kb)
    kb_meta = queries.source_versions(conn) if conn is not None else {}
    kb_sha256 = kb.sha256() if conn is not None else None
    try:
        report = freshness.report(kb.path, kb_sha256, kb_meta, opener, not_ready["reason"] if not_ready else None)
    except releases.ReleaseError as exc:
        raise CallerError(str(exc)) from exc
    return {"kb_ready": conn is not None, "not_ready": not_ready, **report}
