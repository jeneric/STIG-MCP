from contextlib import closing
from pathlib import Path

import pytest

from stig_mcp import applicability
from stig_mcp.ingest.orchestrator import IngestSources, build_kb
from stig_mcp.resolver import resolver as resolver_module
from stig_mcp.resolver.normalize import normalize
from stig_mcp.resolver.resolver import (
    HIGH_CONFIDENCE,
    _alias_ids,
    _corpus,
    _limit_by_benchmark,
    _split,
    _straddling_pairs,
    is_high_confidence,
    resolve,
    score,
    stigs_for_resolver,
)
from tests.conftest import FIX, discovered, open_db_for_test


def test_resolve__known_alias__resolves_to_stig(kb_path):
    conn = open_db_for_test(kb_path)
    hits = resolve(conn, "a RHEL 9 web server")
    assert hits[0]["stig_id"] == "RHEL_9_STIG"
    assert hits[0]["high_confidence"] is True


def test_resolve__unknown_system__returns_empty_or_low_confidence(kb_path):
    conn = open_db_for_test(kb_path)
    hits = resolve(conn, "a mainframe running zOS 2.5")
    assert all(h["score"] < HIGH_CONFIDENCE for h in hits)


def test_resolve__keyword_from_stig_id__matches_via_keyword(kb_path):
    conn = open_db_for_test(kb_path)
    hits = resolve(conn, "rhel")
    assert any(h["stig_id"] == "RHEL_9_STIG" and h["matched_on"] == "keyword" for h in hits)


def test_resolve__multi_system__returns_both_products(kb_path):
    conn = open_db_for_test(kb_path)
    hits = resolve(conn, "RHEL 9 and Windows Server 2022")
    ids = {h["stig_id"] for h in hits}
    assert {"RHEL_9_STIG", "MS_Windows_Server_2022_STIG"} <= ids


def test_resolve__redhat_phrasing__ranks_rhel_above_windows(kb_path):
    conn = open_db_for_test(kb_path)
    hits = resolve(conn, "RedHat Linux Server 9")
    top = next(h for h in hits if h["stig_id"] in {"RHEL_9_STIG", "MS_Windows_Server_2022_STIG"})
    assert top["stig_id"] == "RHEL_9_STIG"


def test_resolve__exact_product_and_version__is_high_confidence(kb_path):
    conn = open_db_for_test(kb_path)
    hits = resolve(conn, "Windows Server 2022")
    win = next(h for h in hits if h["stig_id"] == "MS_Windows_Server_2022_STIG")
    assert win["high_confidence"] is True


def test_alias_ids__empty_pattern_token_set__does_not_match_every_query():
    # A pattern that normalizes to no tokens (e.g. an empty/boilerplate-only string)
    # must never match, since the empty set is a subset of every query.
    stigs = [{"stig_id": "EMPTY_PATTERN_STIG"}]
    aliases = {"EMPTY_PATTERN_STIG": [""]}
    qp, qv = {"anything"}, set()
    assert _alias_ids(qp, qv, stigs, aliases) == set()


def test_alias__an_acronym_pattern__matches_a_spelled_out_query(tmp_path, monkeypatch, wide_kb):
    # Pattern `rhel 9`, query spells the product out. The pattern set carries the literal
    # `rhel`, so without the acronym exemption this match silently dies.
    aliases = tmp_path / "aliases.yaml"
    aliases.write_text('RHEL_9_STIG:\n  - "rhel 9"\n')
    monkeypatch.setattr("stig_mcp.resolver.resolver._ALIASES_PATH", aliases)
    hits = resolve(open_db_for_test(wide_kb), "red hat enterprise linux 9")
    rhel = [h for h in hits if h["stig_id"] == "RHEL_9_STIG"]
    assert rhel and rhel[0]["matched_on"] == "alias:rhel 9"


def test_alias__a_spelled_out_pattern__matches_an_acronym_query(tmp_path, monkeypatch, wide_kb):
    aliases = tmp_path / "aliases.yaml"
    aliases.write_text('RHEL_9_STIG:\n  - "red hat enterprise linux 9"\n')
    monkeypatch.setattr("stig_mcp.resolver.resolver._ALIASES_PATH", aliases)
    hits = resolve(open_db_for_test(wide_kb), "RHEL 9")
    rhel = [h for h in hits if h["stig_id"] == "RHEL_9_STIG"]
    assert rhel and rhel[0]["matched_on"] == "alias:red hat enterprise linux 9"


def test_resolve__an_acronym_query__keeps_confidence_against_a_spelled_out_document(wide_kb):
    # With the acronym in df, `RHEL 9` must still reach RHEL_9_STIG at high confidence.
    # `_keywords` folds the stig_id into product_keywords, so RHEL_9_STIG's own document
    # tokens carry a literal `rhel`, and production aliases.yaml also carries a "rhel 9"
    # entry; either mechanism alone would pass this, so it does not by itself exercise
    # _satisfied's expansion branch. See the WIN 2022 pin below for the case that does.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 9")
    rhel = [h for h in hits if h["stig_id"] == "RHEL_9_STIG"]
    assert rhel and rhel[0]["high_confidence"]


def test_resolve__an_acronym_absent_from_the_docs_own_id__is_satisfied_via_expansion(wide_kb):
    # MS_Windows_Server_2022_STIG folds to "ms windows server 2022 stig": the literal token
    # is `windows`, never `win`, so `win` reaches this document only through _satisfied's
    # expansion branch. Neither alias pattern masks it: "win server 2022" requires `server`,
    # which this query does not supply, so the keyword path is what must carry it.
    hits = resolve(open_db_for_test(wide_kb), "WIN 2022")
    win = [h for h in hits if h["stig_id"] == "MS_Windows_Server_2022_STIG"]
    assert win and win[0]["matched_on"] == "keyword"
    assert win[0]["high_confidence"]


def test_resolve__build_token__is_stripped_before_scoring(tmp_path, monkeypatch, kb_path):
    # Not the high-confidence gate: kb_path's two benchmarks put the distinctiveness threshold
    # (_DISTINCTIVE_DF_RATIO * n) at 0.1, below any real df, so no keyword-path query here is
    # ever high_confidence. The wide_kb tests cover the gate.
    #
    # What this pins: "u3" matches no benchmark title, so if extract_build did not strip it
    # before normalize/score ran, it would count as an unmatched query token and lower the score.
    #
    # Aliases are disabled on purpose: an alias hit scores 100.0 and high_confidence True
    # unconditionally, and every fixture benchmark has one, so with aliases on this pins nothing.
    empty = tmp_path / "aliases.yaml"
    empty.write_text("{}\n")
    monkeypatch.setattr(resolver_module, "_ALIASES_PATH", empty)

    conn = open_db_for_test(kb_path)
    without_build = resolve(conn, "Red Hat Enterprise Linux 9")[0]
    with_build = resolve(conn, "Red Hat Enterprise Linux 9 U3")[0]
    assert with_build["stig_id"] == "RHEL_9_STIG"
    assert with_build["score"] == without_build["score"]


def test_resolve__ungoverned_benchmark_with_a_build__is_applicable_and_flagged(kb_path):
    conn = open_db_for_test(kb_path)
    hit = resolve(conn, "RHEL 9 U3")[0]
    assert hit["applicable"] is True
    assert hit["applicability"] == "ungoverned-build"
    assert hit["build"] == 3


def test_resolve__no_build_supplied__annotates_nothing_for_an_ungoverned_benchmark(kb_path):
    conn = open_db_for_test(kb_path)
    hit = resolve(conn, "RHEL 9")[0]
    assert hit["applicable"] is True
    assert hit["applicability"] is None
    assert hit["build"] is None


RULES_YAML = (
    "TEST_RHEL:\n"
    "  id_pattern: '^RHEL_9_STIG$'\n"
    "  build_pattern: '\\b(?:u(?P<n>\\d+)[a-z]?|ga)\\b'\n"
    "  source: 'test fixture'\n"
    "  verified_against: 'test fixture'\n"
    "  thresholds:\n"
    "    - min: 3\n"
    '      version: "2"\n'
    "    - min: 2\n"
    '      version: "1"\n'
    "    - min: 0\n"
    "      version: null\n"
)


def _governed_kb(tmp_path, monkeypatch, extra_stig_paths=()):
    """A KB holding RHEL_9_STIG at majors 1 and 2 under a governing applicability rule. The
    shared kb_path fixture is single-major on purpose and must not be changed.
    extra_stig_paths adds further compilations to the same build; despite the name, each
    element must be a DiscoveredBenchmark (use discovered()), not a bare path."""
    rules = tmp_path / "rules.yaml"
    rules.write_text(RULES_YAML)
    monkeypatch.setattr(applicability, "RULES_PATH", rules)
    out = tmp_path / "kb.sqlite"
    build_kb(
        IngestSources(
            benchmarks=[discovered(FIX / "rhel9_xccdf.xml"), discovered(FIX / "rhel9_v2_xccdf.xml"), *extra_stig_paths],
            cci_path=FIX / "cci_list.xml",
            attack_path=FIX / "attack_bundle.json",
            ctid_path=FIX / "ctid_mappings.csv",
            overrides_path=FIX / "overrides.yaml",
            catalog_path=FIX / "oscal_catalog.json",
        ),
        out,
    )
    return open_db_for_test(out)


def test_resolve__governed_benchmark_with_a_build__marks_the_other_major_inapplicable(tmp_path, monkeypatch):
    conn = _governed_kb(tmp_path, monkeypatch)
    by_version = {h["version"]: h for h in resolve(conn, "RHEL 9 U3")}
    assert by_version["2"]["applicable"] is True
    assert by_version["2"]["applicability"] == "scoped"
    assert by_version["1"]["applicable"] is False
    assert by_version["1"]["applicability"] == "superseded-major"


def test_resolve__governed_benchmark_before_any_stig__marks_every_major_inapplicable(tmp_path, monkeypatch):
    conn = _governed_kb(tmp_path, monkeypatch)
    hits = resolve(conn, "RHEL 9 U1")
    assert [h["applicable"] for h in hits] == [False, False]
    assert {h["applicability"] for h in hits} == {"no-official-stig"}


def test_resolve__benchmark_with_two_majors__returns_both_versions(tmp_path):
    # A benchmark present as major 1 and major 2 must surface BOTH as candidates,
    # so a caller can pick the version interoperable with their product build.
    fix = Path(__file__).parent.parent / "fixtures"
    out = tmp_path / "kb.sqlite"
    build_kb(
        IngestSources(
            benchmarks=[discovered(fix / "rhel9_xccdf.xml"), discovered(fix / "rhel9_v2_xccdf.xml")],
            cci_path=fix / "cci_list.xml",
            attack_path=fix / "attack_bundle.json",
            ctid_path=fix / "ctid_mappings.csv",
            overrides_path=fix / "overrides.yaml",
        ),
        out,
    )
    conn = open_db_for_test(out)
    rhel = [h for h in resolve(conn, "red hat enterprise linux 9") if h["stig_id"] == "RHEL_9_STIG"]
    assert {h["version"] for h in rhel} == {"1", "2"}


def test_resolve__any_hit__carries_the_same_provenance_as_an_explicit_scope(tie_kb):
    # resolved_systems must have one shape whether the caller passed benchmark_ids or a
    # description; otherwise a description-scoped answer loses its citation silently.
    hit = resolve(tie_kb, "Example Product")[0]
    assert set(hit) >= {
        "origin",
        "release_label",
        "release_info",
        "source_artifact",
        "source_member",
        "xccdf_status",
        "xccdf_status_date",
    }


def test_resolve__equal_scores_across_origins__ranks_the_library_benchmark_first(tie_kb):
    # A tiebreak, never a penalty. A penalty would fight the IDF precision work and
    # would hand someone asking about Windows Server 2019 the 2022 benchmark instead.
    hits = resolve(tie_kb, "Example Product")
    assert [h["origin"] for h in hits][:2] == ["library", "sunset"]
    assert hits[0]["score"] == hits[1]["score"]


def test_resolve__any_hit__reports_its_origin(tie_kb):
    assert all("origin" in h for h in resolve(tie_kb, "Example Product"))


def test_resolve__limit_would_split_a_benchmarks_majors__keeps_both_together(tmp_path, monkeypatch):
    # "Windows Server 2022, RHEL 9 U3" against this KB inserts rows in the order Windows,
    # RHEL v1 (superseded), RHEL v2 (scoped), and every row scores 100.0 via an alias hit, so
    # a stable row-based sort with limit=2 would cut RHEL_9_STIG's applicable v2 row and keep
    # its superseded v1. A row-based `sorted(best.values(), ...)[:limit]` fails this test.
    #
    # resolve() ranks BENCHMARKS (stig_id), not rows: this KB holds only two benchmarks
    # (Windows, RHEL), so limit=2 must keep every row of both, RHEL's applicable v2
    # included, rather than splitting RHEL's two majors across the cut.
    conn = _governed_kb(tmp_path, monkeypatch, extra_stig_paths=[discovered(FIX / "win2022_xccdf.xml")])
    hits = resolve(conn, "Windows Server 2022, RHEL 9 U3", limit=2)
    by_key = {(h["stig_id"], h["version"]): h for h in hits}
    assert ("MS_Windows_Server_2022_STIG", "1") in by_key
    assert ("RHEL_9_STIG", "1") in by_key
    assert ("RHEL_9_STIG", "2") in by_key
    assert by_key[("RHEL_9_STIG", "2")]["applicable"] is True
    assert by_key[("RHEL_9_STIG", "2")]["applicability"] == "scoped"
    assert by_key[("RHEL_9_STIG", "1")]["applicable"] is False
    assert by_key[("RHEL_9_STIG", "1")]["applicability"] == "superseded-major"


def test_resolve__acronym_absent_from_the_benchmark__reaches_it_through_the_synonym(tmp_path):
    # Symantec_Edge_SWG_ALG_STIG carries no "sym" token anywhere in its id, title or
    # keywords, so the synonym expansion is the only thing that can connect the acronym a
    # caller reads off a DISA filename (U_SYM_Edge_SWG_Y26M04_STIG.zip) to the benchmark id
    # inside the archive. Removing the "sym" entry from _SYNONYMS fails this test.
    out = tmp_path / "kb.sqlite"
    build_kb(
        IngestSources(
            benchmarks=[discovered(FIX / "rhel9_xccdf.xml"), discovered(FIX / "symantec_xccdf.xml")],
            cci_path=FIX / "cci_list.xml",
            attack_path=FIX / "attack_bundle.json",
            ctid_path=FIX / "ctid_mappings.csv",
            overrides_path=FIX / "overrides.yaml",
            catalog_path=FIX / "oscal_catalog.json",
        ),
        out,
    )
    with closing(open_db_for_test(out)) as conn:
        hits = resolve(conn, "SYM")
    assert hits, "the acronym must reach a benchmark at all"
    assert hits[0]["stig_id"] == "Symantec_Edge_SWG_ALG_STIG"
    assert hits[0]["matched_on"] == "keyword"
    # Pinned on scoring, not on sort order: a doc sharing no product token scores 0.0, so the
    # non-Symantec benchmark is not a candidate at all and the id assertion carries its own weight
    # rather than resting on an alphabetical tiebreak.
    assert len(hits) == 1


VERDICT = {"verdict": "uncovered", "benchmarks": ["X"], "covered_versions": ["9"], "query_versions": ["8"]}


def test_resolve__single_fragment__hands_the_classifier_every_candidate(kb_path, monkeypatch):
    # limit=1 truncates the result, but the verdict must be decided from every candidate:
    # _limit_by_benchmark cuts score-tied benchmarks on a tiebreak that knows nothing about
    # version coverage, so a verdict read after it could lose the member that makes a tier
    # mixed and report "not covered" when the honest answer is silence.
    seen = {}

    def spy(hits, qp, qv, qm, index, df, n):  # noqa: PLR0913
        seen["ids"] = sorted({hit["stig_id"] for hit in hits})
        seen["qv"] = qv
        return VERDICT

    monkeypatch.setattr(resolver_module, "_version_coverage", spy)
    # A version-only fragment, because the two fixture benchmarks share no product token.
    hits = resolve(open_db_for_test(kb_path), "9 2022", limit=1)
    assert len(hits) == 1
    assert len(seen["ids"]) == 2


def test_resolve__single_fragment__passes_the_fragments_own_version_tokens(kb_path, monkeypatch):
    seen = {}

    def spy(hits, qp, qv, qm, index, df, n):  # noqa: PLR0913
        seen["qv"] = qv
        return VERDICT

    monkeypatch.setattr(resolver_module, "_version_coverage", spy)
    resolve(open_db_for_test(kb_path), "RHEL 8")
    assert seen["qv"] == {"8"}


def test_resolve__a_verdict_was_returned__stamps_it_on_every_row(wide_kb, monkeypatch):
    # Query-level, like `build`. Every row carries the SAME list object, not a copy per row:
    # a copy on every row is the allocation this stamp exists to avoid.
    #
    # 'Fillerware' on wide_kb returns five rows across five benchmarks, so `all(... is first ...)`
    # compares distinct rows; a one-row result would compare the list against itself and miss a
    # list rebuilt per row. The VERDICT line cannot catch that (`list(coverage)` keeps the same
    # verdict dicts); it guards against the list being rebuilt from copies rather than references.
    monkeypatch.setattr(resolver_module, "_version_coverage", lambda *args: VERDICT)
    hits = resolve(open_db_for_test(wide_kb), "Fillerware")
    assert len(hits) > 1
    first = hits[0]["version_coverage"]
    assert all(hit["version_coverage"] is first for hit in hits)
    assert all(hit["version_coverage"][0]["verdict"] is VERDICT["verdict"] for hit in hits)


def test_resolve__two_systems_in_one_description__asks_once_per_fragment(kb_path, monkeypatch):
    # A tier read off the MERGED candidate map belongs to whichever fragment scored highest and
    # cannot attribute an uncovered version to the fragment that named it. Each fragment is
    # classified over its own candidates, so the classifier is asked once per fragment and each
    # answer knows which fragment it speaks for.
    calls = []

    def spy(hits, qp, qv, qm, index, df, n):  # noqa: PLR0913
        calls.append(sorted(qv))
        return VERDICT

    monkeypatch.setattr(resolver_module, "_version_coverage", spy)
    hits = resolve(open_db_for_test(kb_path), "RHEL 9 and Windows Server 2022")
    assert calls == [["9"], ["2022"]]
    assert hits
    assert [v["fragment"] for v in hits[0]["version_coverage"]] == ["RHEL 9", "Windows Server 2022"]


def test_resolve__a_fragment_scoring_nothing__still_gets_asked(kb_path, monkeypatch):
    # A fragment whose candidate map is empty must still reach the classifier rather than be
    # skipped on the way in: _version_coverage's own `if not hits` guard is what decides to stay
    # silent, and moving that decision into resolve() would duplicate the rule in two places.
    seen = []

    def spy(hits, qp, qv, qm, index, df, n):  # noqa: PLR0913
        seen.append(len(list(hits)))

    monkeypatch.setattr(resolver_module, "_version_coverage", spy)
    resolve(open_db_for_test(kb_path), "RHEL 9 and Zzqxnonexistent")
    assert len(seen) == 2
    assert seen[1] == 0


def test_resolve__classifier_declines__leaves_every_row_with_no_verdict(kb_path, monkeypatch):
    monkeypatch.setattr(resolver_module, "_version_coverage", lambda *args: None)
    hits = resolve(open_db_for_test(kb_path), "server")
    assert hits
    assert all(hit["version_coverage"] == [] for hit in hits)


def test_resolve__version_the_corpus_lacks__stamps_an_uncovered_verdict(wide_kb):
    # The real join, no spy: a corpus large enough for a distinctive token, a query naming
    # a version it does not hold, and the verdict computed from it. The tests above pin the
    # wiring; this one pins that the wiring carries a real classification.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 8")
    assert hits[0]["version_coverage"] == [
        {
            "verdict": "uncovered",
            "benchmarks": ["RHEL_9_STIG"],
            "covered_versions": ["9"],
            "query_versions": ["8"],
            "fragment": "RHEL 8",
            "fragment_confident": False,
            "matched_benchmarks": ["RHEL_9_STIG"],
        }
    ]


def test_resolve__version_is_held__stamps_no_verdict(wide_kb):
    # One version along from the test above, over the same corpus. A false "not covered" is
    # the expensive failure the classifier is shaped around, so the silence needs its own
    # end-to-end proof.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 9")
    assert hits[0]["stig_id"] == "RHEL_9_STIG"
    assert hits[0]["version_coverage"] == []


def test_resolve__query_names_a_patch_level_of_a_held_major__stamps_no_verdict(wide_kb):
    # The real join for the majors rule: 'RHEL 9.4' normalizes to the versions {9, 4}, and
    # RHEL_9_STIG covers only 9. Judged on the whole token set this denies a benchmark the
    # same call is about to return. It must be a verdict assertion and not a notes
    # assertion: the rhel alias makes this query auto-scope, so the note path never runs.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 9.4")
    assert hits[0]["stig_id"] == "RHEL_9_STIG"
    assert hits[0]["version_coverage"] == []


def test_resolve__an_absent_major_with_a_minor_the_corpus_holds__stamps_an_uncovered_verdict(wide_kb):
    # 'RHEL 8.9': the major, 8, is genuinely absent from this corpus, and the minor
    # coinciding with RHEL_9_STIG's 9 must not buy silence. This is what pins the verdict to
    # _version_majors(fragment) rather than to the whole version-token set, which would go
    # silent here on the coincidence alone.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 8.9")
    assert hits[0]["version_coverage"][0]["verdict"] == "uncovered"
    assert hits[0]["version_coverage"][0]["covered_versions"] == ["9"]


def test_resolve__a_version_glued_to_a_letter_in_the_title__reports_it_as_covered(wide_kb):
    # NOVAFLOW_DATABASE_19C_STIG is the Oracle 19c shape. The classifier's index reads 19 out of
    # '19c' (via `glued_versions`, never via `normalize`), so the tier is version-pinned and the
    # caller is told which version it holds. Calling it "not version-specific" would invite the
    # caller to apply 19c remediation to a 12c database.
    hits = resolve(open_db_for_test(wide_kb), "Novaflow Database 12")
    assert hits[0]["stig_id"] == "NOVAFLOW_DATABASE_19C_STIG"
    assert hits[0]["version_coverage"][0]["verdict"] == "uncovered"
    assert hits[0]["version_coverage"][0]["covered_versions"] == ["19"]


def test_resolve__a_confident_benchmark_outranked_by_others__is_not_reported_confident(wide_kb):
    # Confidence answers "does this benchmark hold everything the caller named", which a benchmark
    # can satisfy on one rare shared token while better answers outrank it. Without a rank check,
    # `IBM z OS ACF2 19c` would auto-scope to Oracle_Database_19c_STIG from fifth place, behind
    # four ACF2 benchmarks.
    #
    # Reproduced with three filler tokens (df 19 of 29, so not distinctive) plus `19c`, which only
    # NOVAFLOW holds: the fillers cover more of the query and outrank it, while NOVAFLOW is the only
    # benchmark holding every distinctive token the query named. limit=25 because 19 fillers tie
    # above it and would otherwise fill the five-benchmark window.
    hits = resolve(open_db_for_test(wide_kb), "filler padding appliance 19c", limit=25)
    ranked = {hit["stig_id"]: hit for hit in hits}
    novaflow = ranked["NOVAFLOW_DATABASE_19C_STIG"]
    assert novaflow["score"] < hits[0]["score"], "the fixture must keep NOVAFLOW below the top"
    assert not hits[0]["high_confidence"], "and nothing above it may be confident either"
    assert not novaflow["high_confidence"]


def test_resolve__a_glued_version_in_the_callers_text__does_not_reach_a_bare_digit_alias(wide_kb):
    # Guards the CALL SITE, not normalize's default. resolve() must ask for glued_versions on the
    # document side only; the unit test one file over pins the default and cannot see whether
    # `resolve` opts the caller's text in too.
    #
    # `RHEL v9` is the whole failure in miniature. _alias_ids tests its pattern against `qp | qv`,
    # so a version derived from the caller's `v9` would satisfy the `rhel 9` pattern, and an alias
    # hit is scored 100.0 and confident outright, turning an unconfident keyword hit into a
    # confident scope.
    hits = resolve(open_db_for_test(wide_kb), "RHEL v9")
    assert hits[0]["stig_id"] == "RHEL_9_STIG"
    assert hits[0]["matched_on"] == "keyword"
    assert not hits[0]["high_confidence"]


@pytest.mark.parametrize(
    ("query", "benchmark"),
    [("Orbital Datastore 10", "ORBITAL_DATASTORE_V10-5_STIG"), ("Novaflow Database 19", "NOVAFLOW_DATABASE_19C_STIG")],
)
def test_resolve__a_glued_version__does_not_earn_the_benchmark_version_credit(query, benchmark, wide_kb):
    # The separation this design exists for. `glued_versions` may widen the CLASSIFIER's index
    # and nothing else: a version token in the scoring sets reaches build_idf, score and
    # is_high_confidence, and `EDB Postgres Advanced Server v11 on Windows` would gain version 11
    # while already holding `windows`, tying Microsoft_Windows_11_STIG at 100.0 AND high
    # confidence for 'Windows 11'.
    #
    # Observable here as the version half of the score: these benchmarks write their version glued,
    # so a caller naming it bare must NOT collect the 20 points, and must not be auto-scoped.
    hits = resolve(open_db_for_test(wide_kb), query)
    assert hits[0]["stig_id"] == benchmark
    # Exact compare is safe for these two queries only: each names two product tokens, and a
    # two-term float sum is order-independent, so _coverage returns exactly 1.0. A three-token
    # query here would flake, since numerator and denominator sum over different sets.
    assert hits[0]["score"] == 80.0, "100.0 means a glued version reached the scoring token sets"
    assert not hits[0]["high_confidence"]


def test_resolve__a_v_prefixed_version_the_tier_holds__stamps_no_verdict(wide_kb):
    # The v-prefixed half of the glued rule, end to end. ORBITAL_DATASTORE_V10-5 covers 10.5, so a
    # caller naming 10 has named a version it holds and must hear nothing. Without the rule the
    # benchmark's tokens hold only the minor, `10` matches nothing in them, and the caller is told
    # "no STIG for Orbital Datastore 10 ... covering 10.5", denying the version it grants one
    # clause later. The unit tests cover the tokenizing; this covers the answer.
    hits = resolve(open_db_for_test(wide_kb), "Orbital Datastore 10")
    assert hits[0]["stig_id"] == "ORBITAL_DATASTORE_V10-5_STIG"
    assert hits[0]["version_coverage"] == []


def test_resolve__a_dotted_version_in_the_title__is_carried_through_as_written(wide_kb):
    # The whole join for the written form: resolve() builds the index from titles, so this
    # dies if that ever reverts to the version tokens, which would render '0, 10' for 10.0.
    hits = resolve(open_db_for_test(wide_kb), "Zephyr Gateway 9.0")
    assert hits[0]["version_coverage"][0]["covered_versions"] == ["10.0"]


def test_resolve__a_version_whose_major_is_glued_to_a_letter__renders_the_whole_version(wide_kb):
    # ORBITAL_DATASTORE_V10-5_STIG is the IBM DB2 V10.5 LUW shape: _WORD_RE splits the title into
    # 'v10' and '5', so the note must say 10.5 rather than the 5 that a token-only reading leaves.
    # normalize recovers the 10 from 'v10', but the tokens are a flat set: only the title's written
    # run knows the two belong to one version.
    hits = resolve(open_db_for_test(wide_kb), "Orbital Datastore 11")
    assert hits[0]["version_coverage"][0]["covered_versions"] == ["10.5"]


def test_resolve__a_title_run_no_version_token_confirms__stamps_no_verdict(wide_kb):
    # SENTINEL_4180X_RELAY_STIG is the `SEL-2740S` and `HPE 3PAR SSMC` shape: _VERSION_RUN_RE reads
    # `4180` out of a MODEL NUMBER, while neither the tokens nor a curated entry confirm it. The two
    # readings disagree, so neither can be trusted and the answer is silence. Calling such a tier
    # "not version-specific" is a false statement about the knowledge base AND an invitation to
    # apply Oracle 19c remediation to a 12c database. This is the guard's resolver-level
    # end-to-end pin; test_tools.py pins the note path.
    hits = resolve(open_db_for_test(wide_kb), "Sentinel 4180X Relay 9")
    assert hits[0]["stig_id"] == "SENTINEL_4180X_RELAY_STIG"
    assert hits[0]["version_coverage"] == []


def test_resolve__a_digit_in_the_products_name__still_reports_version_agnostic(wide_kb):
    # NIMBUS7_RELAY_STIG is the F5 BIG-IP shape: the 7 belongs to the product's name, so the
    # benchmark genuinely is not version-specific and the note must survive.
    hits = resolve(open_db_for_test(wide_kb), "Nimbus7 Relay 3")
    assert hits[0]["stig_id"] == "NIMBUS7_RELAY_STIG"
    assert hits[0]["version_coverage"][0]["verdict"] == "version-agnostic"


def test_resolve__the_query_pads_a_held_version_with_a_zero__stamps_no_verdict(wide_kb):
    # 'RHEL 09' is RHEL 9, which this corpus holds. Denying it while listing it as covered is the
    # contradiction the version key exists to stop.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 09")
    assert hits[0]["stig_id"] == "RHEL_9_STIG"
    assert hits[0]["version_coverage"] == []


def test_resolve__a_bare_version_against_a_padded_benchmark_version__reports_it_uncovered(wide_kb):
    # Version matching is asymmetric. Canonical writes 22.04, so the tier holds the token 04 while
    # this caller asks for 4, a version this knowledge base genuinely does not hold. Unpadding
    # DISA's side as well would silence this note and, in scoring, auto-scope this caller to
    # Ubuntu 22.04 confidently.
    hits = resolve(open_db_for_test(wide_kb), "Ubuntu 4")
    assert hits[0]["stig_id"] == "CAN_UBUNTU_22-04_LTS_STIG"
    assert hits[0]["version_coverage"][0]["verdict"] == "uncovered"
    assert hits[0]["version_coverage"][0]["covered_versions"] == ["22.04"]


def test_score__a_padded_query_version__scores_as_an_exact_match():
    # Unit level, and it has to be: driven through resolve() on a benchmark carrying an alias, the
    # alias path returns 100.0 and high confidence on its own, so an end-to-end assertion passes
    # whatever score() does, including a raw intersection.
    assert score({"foo"}, {"08"}, {"foo"}, {"8"}, {}) == score({"foo"}, {"8"}, {"foo"}, {"8"}, {}) == 100.0


def test_is_high_confidence__a_padded_query_version__is_confident():
    # Same reasoning as above, and this is the field that decides auto-scoping.
    df, n = {"foo": 1}, 100
    assert is_high_confidence({"foo"}, {"08"}, {"foo"}, {"8"}, df, n) is True
    assert is_high_confidence({"foo"}, {"8"}, {"foo"}, {"8"}, df, n) is True


def test_is_high_confidence__a_bare_query_version_against_a_padded_doc_version__is_not_confident():
    # The asymmetry, at the field that auto-scopes: a caller who says 4 must not be scoped to 04.
    assert is_high_confidence({"foo"}, {"4"}, {"foo"}, {"04"}, {"foo": 1}, 100) is False


def test_resolve__a_padded_caller_version__is_high_confidence(wide_kb):
    # End to end on ZEPHYR_GATEWAY_10-0_STIG, which carries no alias, so this reaches score() and
    # is_high_confidence() rather than being answered by the alias path.
    conn = open_db_for_test(wide_kb)
    padded = resolve(conn, "Zephyr Gateway 010.0")
    bare = resolve(conn, "Zephyr Gateway 10.0")
    assert padded[0]["stig_id"] == bare[0]["stig_id"] == "ZEPHYR_GATEWAY_10-0_STIG"
    assert padded[0]["matched_on"] == "keyword"
    assert padded[0]["high_confidence"] is True
    assert padded[0]["score"] == bare[0]["score"]


def test_resolve__a_bare_version_against_a_padded_benchmark_version__stays_low_confidence(wide_kb):
    # The other direction must NOT match: Canonical writes 22.04, and a caller saying 'Ubuntu 4'
    # must not be auto-scoped to it.
    hits = resolve(open_db_for_test(wide_kb), "Ubuntu 4")
    assert hits[0]["stig_id"] == "CAN_UBUNTU_22-04_LTS_STIG"
    assert all(hit["high_confidence"] is False for hit in hits)


def test_alias_ids__a_padded_caller_version__still_reaches_the_alias(kb_path):
    # An alias pattern is authored here, so the caller's spelling has to reach it: 'RHEL 09' must
    # match the same alias 'RHEL 9' does. Otherwise a padded caller matches on keywords alone and
    # silently loses every alias, so the two spellings give different answers.
    with closing(open_db_for_test(kb_path)) as conn:
        stigs = stigs_for_resolver(conn)
    aliases = {"RHEL_9_STIG": ["RHEL 9"]}
    padded_query = normalize("a RHEL 09 web server")
    bare_query = normalize("a RHEL 9 web server")
    padded = _alias_ids(padded_query.product, padded_query.version, stigs, aliases)
    bare = _alias_ids(bare_query.product, bare_query.version, stigs, aliases)
    assert padded == bare == {("RHEL_9_STIG", "RHEL 9")}


def test_score__a_version_only_query__scores_the_padded_and_bare_spelling_identically():
    # The no-product branch of score, at unit level with a REAL idf and two version tokens. Both
    # matter: driven through resolve() on the two-benchmark fixture with one token, the numerator
    # and denominator cancel and the assertion cannot see the weighting at all.
    idf = {"1": 4.88, "0": 2.10, "10": 3.90}
    doc_holds_one = ({"foo"}, {"1", "0"})
    doc_holds_ten = ({"foo"}, {"10", "0"})
    for dp, dv in (doc_holds_one, doc_holds_ten):
        assert score(set(), {"1", "0"}, dp, dv, idf) == score(set(), {"01", "0"}, dp, dv, idf)


def test_score__a_padded_version_only_query__is_weighted_as_the_version_it_names():
    # Not merely equal to the bare spelling: weighted by the real token. A padded token is absent
    # from the corpus, so left alone it would be charged the 1.0 default and a doc holding a
    # different version would outrank the doc that holds the one named.
    idf = {"1": 4.88, "0": 2.10, "10": 3.90}
    holds_one = score(set(), {"01", "0"}, {"foo"}, {"1", "0"}, idf)
    holds_ten = score(set(), {"01", "0"}, {"foo"}, {"10", "0"}, idf)
    assert holds_one > holds_ten


def test_is_high_confidence__one_version_token_unmatched__is_not_confident():
    # The ALL half of the version test, which the padding relation must not weaken to ANY: a query
    # naming two versions where the benchmark holds one is not an answer, it is a candidate.
    assert is_high_confidence({"foo"}, {"08", "7"}, {"foo"}, {"8"}, {"foo": 1}, 100) is False


def test_resolve__a_query_naming_a_version_the_benchmark_lacks__is_not_confident(wide_kb):
    # The same property end to end, on ZEPHYR_GATEWAY_10-0_STIG, which carries no alias: 10.0.7
    # names a patch level the benchmark does not hold, so it must not auto-scope.
    hits = resolve(open_db_for_test(wide_kb), "Zephyr Gateway 10.0.7")
    assert hits[0]["stig_id"] == "ZEPHYR_GATEWAY_10-0_STIG"
    assert hits[0]["high_confidence"] is False


def test_alias_ids__the_unpadded_form__is_added_to_the_query_not_substituted_for_it(kb_path):
    # The unpadded spelling joins the query's tokens rather than replacing them, so a pattern
    # written with the padded form still matches a caller who wrote it that way.
    with closing(open_db_for_test(kb_path)) as conn:
        stigs = stigs_for_resolver(conn)
    aliases = {"RHEL_9_STIG": ["RHEL 09"]}
    query = normalize("a RHEL 09 web server")
    assert _alias_ids(query.product, query.version, stigs, aliases) == {("RHEL_9_STIG", "RHEL 09")}


def test_score__a_version_only_query_the_corpus_writes_padded__still_reaches_a_bare_benchmark():
    # The one shape that needs BOTH halves of the version-only branch. '04' is a real corpus token
    # (Canonical writes 22.04), so rewriting to the corpus spelling leaves it alone, and only the
    # padding-tolerant relation gets it to a benchmark that writes the same version as 4.
    idf = {"04": 3.0, "4": 3.0}
    assert score(set(), {"04"}, {"foo"}, {"4"}, idf) == 100.0


def test_score__a_bare_version_only_query__is_not_rewritten_to_a_padded_corpus_spelling():
    # _as_corpus_versions rewrites one way. Preferring the corpus's padded spelling instead would
    # take the query '4' from 0.0 to 100.0 against Canonical Ubuntu 22.04, which is the conflation
    # the whole asymmetry exists to forbid, and no other test in the suite could see it.
    assert score(set(), {"4"}, {"foo"}, {"04"}, {"04": 3.0, "4": 3.0}) == 0.0


def test_resolve__parent_ties_with_its_components__ranks_the_parent_first(component_family_kb):
    # The vCenter shape in miniature. 'Vectrix Orchestrator' names every token of the
    # parent's title and only part of each child's, so all four score identically and an
    # alphabetical tiebreak alone would rank the parent LAST of four and cut it away.
    with closing(open_db_for_test(component_family_kb)) as conn:
        hits = resolve(conn, "Vectrix Orchestrator", limit=2)
    ids = [hit["stig_id"] for hit in hits]
    assert "VECTRIX_ORCHESTRATOR_STIG" in ids, "the benchmark the query named was cut from the result"
    assert ids[0] == "VECTRIX_ORCHESTRATOR_STIG"


def test_resolve__parent_ties_with_its_components__all_four_score_identically(component_family_kb):
    # A fixture-validity check: every other assertion about this fixture is worthless if the
    # four candidates do not actually tie on score.
    with closing(open_db_for_test(component_family_kb)) as conn:
        hits = resolve(conn, "Vectrix Orchestrator", limit=4)
    scores = {hit["score"] for hit in hits}
    assert len(hits) == 4
    assert len(scores) == 1, f"the four candidates must tie, else the fixture proves nothing: {scores}"


def test_resolve__query_names_a_component__leaves_that_component_first(component_family_kb):
    # The shape a specificity tiebreak could break: preferring the shortest title must not
    # demote a component when the caller asks for one. It does not, because naming the
    # component scores it strictly higher rather than tying.
    with closing(open_db_for_test(component_family_kb)) as conn:
        hits = resolve(conn, "Vectrix Orchestrator Cluster Ledger", limit=2)
    assert hits[0]["stig_id"] == "VECTRIX_ORCHESTRATOR_CLUSTER_LEDGER_STIG"


def test_resolve__three_components_tie_on_everything_but_stig_id__orders_them_alphabetically(component_family_kb):
    # The three Vectrix children tie with each other on score, origin AND specificity (each
    # adds exactly "cluster" plus its own name to the parent's tokens), so stig_id is the
    # only thing left to decide their order: INGEST, LEDGER, PORTAL, in that ASCII order.
    with closing(open_db_for_test(component_family_kb)) as conn:
        hits = resolve(conn, "Vectrix Orchestrator", limit=4)
    assert [hit["stig_id"] for hit in hits] == [
        "VECTRIX_ORCHESTRATOR_STIG",
        "VECTRIX_ORCHESTRATOR_CLUSTER_INGEST_STIG",
        "VECTRIX_ORCHESTRATOR_CLUSTER_LEDGER_STIG",
        "VECTRIX_ORCHESTRATOR_CLUSTER_PORTAL_STIG",
    ]


def test_limit_by_benchmark__score_origin_and_specificity_all_tie__stig_id_decides():
    # A direct check on the sort itself, not through resolve(). stigs_for_resolver always
    # hands resolve() its rows pre-sorted by stig_id, and Python's sort is stable, so a query
    # tied all the way down would come out alphabetical even with stig_id silently dropped
    # from the rank key: the input order coming OUT of resolve() would already be right by
    # accident. Feeding _limit_by_benchmark two hits reverse-alphabetical, tied on
    # everything else, is what actually forces the sort to move them.
    # high_confidence is part of the hit contract (resolve() sets it on every row) and the
    # rank key reads it, so a synthetic hit has to carry it too. Equal here, so it decides
    # nothing and stig_id still does.
    hits = [
        {"score": 100.0, "origin": "library", "stig_id": "ZULU_STIG", "version": "1", "high_confidence": False},
        {"score": 100.0, "origin": "library", "stig_id": "ALPHA_STIG", "version": "1", "high_confidence": False},
    ]
    unnamed = {"ZULU_STIG": 0, "ALPHA_STIG": 0}
    kept, tied_omitted = resolver_module._limit_by_benchmark(hits, 2, unnamed)
    assert [hit["stig_id"] for hit in kept] == ["ALPHA_STIG", "ZULU_STIG"]
    assert tied_omitted == 0


def test_resolve__library_benchmark_carries_more_unnamed_tokens__origin_still_wins(origin_over_specificity_kb):
    # origin_over_specificity_kb's library row names 3 keywords the query does not (worse
    # specificity than the sunset row's 0), so a sort that read specificity before origin
    # would put the sunset benchmark on top. It does not, because _origin_rank is read first.
    hits = resolve(origin_over_specificity_kb, "Gadget Widget", limit=2)
    assert hits[0]["stig_id"] == "GADGET_WIDGET_FULL_STIG"
    assert hits[0]["origin"] == "library"
    assert hits[0]["score"] == hits[1]["score"]


def test_resolve__multi_major_benchmark__specificity_reduces_by_min_across_majors(multi_major_specificity_kb):
    # multi_major_specificity_kb's MULTI_MAJOR_STIG has a lean major (1 unnamed keyword) and
    # a noisy one (5), straddling RIVAL_STIG's 3. Only the min of the two majors (1) beats
    # RIVAL; the max (5) or whichever major resolve() happened to process last would not.
    hits = resolve(multi_major_specificity_kb, "Multi Major", limit=2)
    assert hits[0]["stig_id"] == "MULTI_MAJOR_STIG"
    assert {hit["stig_id"] for hit in hits} == {"MULTI_MAJOR_STIG", "RIVAL_STIG"}
    assert {hit["version"] for hit in hits if hit["stig_id"] == "MULTI_MAJOR_STIG"} == {"1", "2"}


def test_resolve__benchmarks_differing_only_in_version_tokens__specificity_counts_them(
    version_specificity_kb,
):
    # The specificity count is len((dp | dv) - (qp | qv)), which is what _limit_by_benchmark's
    # docstring means by unnamed document tokens. Here the product half is
    # 0 for both rows, so only the version half can separate them: GIZMO_ZEBRA_STIG's document
    # holds the query's 7 and nothing else, while GIZMO_ALPHA_STIG's 7.8.9 leaves 8 and 9
    # unnamed. len(dp - qp) and len(dp - (qp | qv)) both tie them at 0 and hand the order to
    # stig_id, which puts ALPHA first.
    #
    # Deliberately unpinned: dropping only `qv`, as len((dp | dv) - qp). Rows with an identical
    # product half shift both counts equally, so this fixture cannot see it; separating it needs
    # a score tie by compensation (one row paying a product deficit with version coverage) exact
    # to the last bit, and a fixture resting on an exact float coincidence is the fragile kind.
    hits = resolve(version_specificity_kb, "Gizmo 7", limit=2)
    assert [hit["stig_id"] for hit in hits] == ["GIZMO_ZEBRA_STIG", "GIZMO_ALPHA_STIG"]
    assert hits[0]["score"] == hits[1]["score"] == 100.0


def test_resolve__a_later_fragment_outscores_an_earlier_one__specificity_comes_from_the_winner(
    fragment_win_specificity_kb,
):
    # When a later fragment outscores an earlier one for the same key, the winner's unnamed
    # count is recorded, not a running min across every fragment that ever won the key (the
    # 'vSphere 8.0, vCenter' shape). Here TARGET_STIG's first fragment ('Alpha Beta Junk1 Junk2
    # Gamma') wins it a sub-100 score with 2 unnamed document tokens; its second fragment
    # ('Beta') then wins it 100.0 with 5 unnamed document tokens, and 5 is what must be
    # recorded, not the stale 2. RIVAL_STIG's fixed 3 unnamed document tokens sit strictly
    # between the two, so RIVAL must outrank TARGET.
    hits = resolve(fragment_win_specificity_kb, "Alpha Beta Junk1 Junk2 Gamma, Beta", limit=2)
    assert hits[0]["stig_id"] == "RIVAL_STIG"
    assert hits[0]["score"] == hits[1]["score"] == 100.0


def test_resolve__a_later_fragment_ties__specificity_stays_with_the_earlier_fragment(
    fragment_tie_specificity_kb,
):
    # The `>` in resolve()'s `hit_score > current["score"]` evaluating FALSE on a TIE, which
    # nothing else in the suite reaches: the losing-fragment test below reaches the same arc,
    # but through a strict loss. That branch decides which fragment's unnamed count a
    # benchmark is ranked by.
    #
    # AAA_TARGET_STIG scores 100.0 on 'zzalpha' with 5 unnamed document tokens, then 100.0
    # again on 'zzalpha zzbeta zzgamma zzdelta' with 2. A tie is not a strict win, so the 5
    # stands and ZZZ_RIVAL_STIG's 3 beats it, even though ZZZ sorts last on stig_id. Relaxing
    # the comparison to `>=`, or writing unnamed_by_key outside the branch, would record the 2
    # and put AAA_TARGET_STIG first.
    hits = resolve(fragment_tie_specificity_kb, "zzalpha and zzalpha zzbeta zzgamma zzdelta", limit=2)
    assert [hit["stig_id"] for hit in hits] == ["ZZZ_RIVAL_STIG", "AAA_TARGET_STIG"]
    assert hits[0]["score"] == hits[1]["score"] == 100.0


def test_resolve__the_winning_fragment_names_more__its_lower_count_is_the_one_recorded(
    losing_fragment_specificity_kb,
):
    # The direction both other fragment tests leave open. Here the winning fragment carries
    # the LOWER count: ZZZ_TARGET_STIG scores 53.3 on 'zzalpha zzbeta' with 5 unnamed document
    # tokens, then 100.0 on 'zzq zzbeta zzgamma zzdelta zzeps' with 1, and 1 is what must be
    # recorded, so TARGET beats AAA_RIVAL_STIG's 3 despite sorting last on stig_id.
    #
    # Without this, replacing the in-branch write with a running max outside it passes the
    # whole suite: the other two fixtures both give their surviving fragment the HIGHER count,
    # so max reproduces the right answer for the wrong reason. Here max gives TARGET 5 against
    # RIVAL's 4 and reverses the order, which is what separates "the winner's count" from
    # "the largest count any fragment produced".
    hits = resolve(losing_fragment_specificity_kb, "zzalpha zzbeta, zzq zzbeta zzgamma zzdelta zzeps", limit=2)
    assert [hit["stig_id"] for hit in hits] == ["ZZZ_TARGET_STIG", "AAA_RIVAL_STIG"]
    assert hits[0]["score"] == hits[1]["score"] == 100.0


def test_resolve__the_appliance_acronym__reaches_the_vcenter_parent(vsphere_appliance_kb):
    # VCSA is the vCenter Server Appliance. Without the parent's alias this ranks the component
    # STIGs only, excluding the very benchmark the caller most likely meant: the parent's
    # document carries no `vcsa` token, because DISA spells its id vCenter while the components
    # spell theirs VCSA. On the real knowledge base the components are additionally
    # high_confidence, so _resolve_scope would auto-scope to them; this fixture pins the ranking
    # half of that only, for the reason its docstring gives.
    hits = resolve(vsphere_appliance_kb, "VCSA 8.0", limit=5)
    assert hits[0]["stig_id"] == "VMW_vSphere_8-0_vCenter_STIG"
    assert hits[0]["matched_on"] == "alias:vcsa 8"
    assert hits[0]["high_confidence"] is True


def test_resolve__the_appliance_without_the_minor_version__reaches_the_vcenter_parent(vsphere_appliance_kb):
    # Why the pattern is `vcsa 8` and not `vcsa 8.0`. _alias_ids is a subset test and normalize
    # splits 8.0 into {8, 0}, so a `vcsa 8.0` pattern needs all three tokens and would miss
    # 'VCSA 8'. The shorter pattern covers both spellings at once.
    hits = resolve(vsphere_appliance_kb, "VCSA 8", limit=5)
    assert hits[0]["stig_id"] == "VMW_vSphere_8-0_vCenter_STIG"
    assert hits[0]["matched_on"] == "alias:vcsa 8"


def test_resolve__the_appliance_spelled_out_plus_a_component__leaves_the_parent_unaliased(vsphere_appliance_kb):
    # Pins the rejection of a second pattern, 'vcenter server appliance 8.0'. The two spellings
    # are not symmetric: components carry `vcsa` in their ids, so the acronym makes the parent
    # JOIN their tied tier, but they carry none of vcenter/server/appliance, so the spelled-out
    # pattern would score the parent 100.0 alone and evict the component the caller just named.
    # This asserts the unaliased ranking, and fails the moment that pattern is added back.
    hits = resolve(vsphere_appliance_kb, "vCenter Server Appliance 8.0 Photon OS", limit=5)
    assert hits[0]["stig_id"] == "VMW_vSphere_8-0_VCSA_Photon_OS_4-0_STIG"
    parent = next(hit for hit in hits if hit["stig_id"] == "VMW_vSphere_8-0_vCenter_STIG")
    assert parent["matched_on"] == "keyword"


def test_resolve__the_appliance_plus_a_component__keeps_that_component_in_the_top_tier(vsphere_appliance_kb):
    # Why only the PARENT is aliased. Aliasing all ten benchmarks answers 'VCSA 8.0' the same
    # way but ties every component at 100.0 here, burying Photon among its siblings. With the
    # parent alone, the components still rank on their own keyword score, so naming one keeps
    # it at the top and drops the rest.
    hits = resolve(vsphere_appliance_kb, "VCSA 8.0 Photon OS", limit=5)
    top = [hit["stig_id"] for hit in hits[:2]]
    assert "VMW_vSphere_8-0_VCSA_Photon_OS_4-0_STIG" in top
    photon = next(h for h in hits if h["stig_id"] == "VMW_vSphere_8-0_VCSA_Photon_OS_4-0_STIG")
    envoy = next(h for h in hits if h["stig_id"] == "VMW_vSphere_8-0_VCSA_Envoy_STIG")
    assert photon["score"] > envoy["score"]


def test_resolve__tier_wider_than_the_limit__reports_the_tied_benchmarks_it_dropped(component_family_kb):
    with closing(open_db_for_test(component_family_kb)) as conn:
        hits = resolve(conn, "Vectrix Orchestrator", limit=2)
    assert {hit["tied_omitted"] for hit in hits} == {2}


def test_resolve__tier_fits_inside_the_limit__reports_nothing_dropped(component_family_kb):
    with closing(open_db_for_test(component_family_kb)) as conn:
        hits = resolve(conn, "Vectrix Orchestrator", limit=4)
    assert {hit["tied_omitted"] for hit in hits} == {0}


def test_resolve__cut_lands_on_a_score_boundary__counts_only_the_tied_losers(component_family_kb):
    # Naming a component scores it above its three siblings, so a limit of 1 cuts a score
    # BOUNDARY rather than a tier. Nothing was dropped arbitrarily and the count stays 0.
    with closing(open_db_for_test(component_family_kb)) as conn:
        hits = resolve(conn, "Vectrix Orchestrator Cluster Ledger", limit=1)
    assert [hit["stig_id"] for hit in hits] == ["VECTRIX_ORCHESTRATOR_CLUSTER_LEDGER_STIG"]
    assert hits[0]["tied_omitted"] == 0


def test_resolve__the_kept_tier_and_the_top_score_differ__cutoff_is_the_last_row_kept(component_family_kb):
    # Naming Ledger scores it above its three siblings (100.0), and the two remaining
    # siblings (Ingest, Portal) tie with each other below it (70.17...), strictly above the
    # parent (51.13...). A limit of 2 keeps Ledger and one of the tied siblings, so the top
    # score (100.0) and the last-kept row's score (70.17...) are DIFFERENT numbers here,
    # which is what this fixture is for: a cutoff read off ranked[0] (the top score) would
    # find nothing else that close and report 0, where the true cutoff is the last KEPT
    # row's score, which the other tied sibling matches, so the correct count is 1.
    with closing(open_db_for_test(component_family_kb)) as conn:
        hits = resolve(conn, "Vectrix Orchestrator Cluster Ledger", limit=2)
    assert [hit["stig_id"] for hit in hits] == [
        "VECTRIX_ORCHESTRATOR_CLUSTER_LEDGER_STIG",
        "VECTRIX_ORCHESTRATOR_CLUSTER_INGEST_STIG",
    ]
    assert hits[0]["score"] != hits[1]["score"]
    assert {hit["tied_omitted"] for hit in hits} == {1}


def test_resolve__a_tie_split_by_confidence__ranks_the_confident_row_first(confident_tie_kb):
    # A rank key that ignores confidence orders six benchmarks tied on score by origin,
    # specificity and then stig_id, and the five unconfident rivals take every slot. On the real
    # knowledge base that is 'tier 4': eight NSX rows tie at 63.66 and _resolve_scope auto-scopes
    # to ONE of the four confident 4.x benchmarks.
    hits = resolve(confident_tie_kb, "zzalpha tier 4", limit=5)
    assert hits[0]["stig_id"] == "ZZZ_TARGET_STIG"
    assert len({hit["score"] for hit in hits}) == 1, "the fixture is only meaningful while every row ties"


def test_resolve__a_confident_row_behind_five_rivals__survives_the_cap(confident_tie_kb):
    # The consequence that reaches a caller. tools._resolve_scope filters high_confidence out of
    # an ALREADY CAPPED list, so a confident benchmark cut by the limit is not merely ranked
    # lower, it is absent from the scope entirely and the caller is told nothing was identified.
    hits = resolve(confident_tie_kb, "zzalpha tier 4", limit=5)
    assert [hit["stig_id"] for hit in hits if hit["high_confidence"]] == ["ZZZ_TARGET_STIG"]


def test_limit_by_benchmark__a_higher_scoring_unconfident_row__still_outranks_a_confident_one():
    # Confidence sits AFTER score in the key. Fed directly because NO fixture can express this
    # case: resolve() clears `high_confidence` on every row more than `_SCORE_TIE_EPSILON`
    # below the top score before `_limit_by_benchmark` ever sees it, so a confident row that is
    # not top-scoring cannot reach the rank key by any route. This pins the key's own contract,
    # and is the only thing that fails if the term is moved ahead of score.
    hits = [
        {"stig_id": "AAA_LOUD_STIG", "version": "1", "score": 80.0, "high_confidence": False, "origin": "library"},
        {"stig_id": "BBB_SURE_STIG", "version": "1", "score": 70.0, "high_confidence": True, "origin": "library"},
    ]
    unnamed = {"AAA_LOUD_STIG": 0, "BBB_SURE_STIG": 0}
    kept, _omitted = _limit_by_benchmark(hits, 2, unnamed)
    assert [hit["stig_id"] for hit in kept] == ["AAA_LOUD_STIG", "BBB_SURE_STIG"]


def test_split__a_separator_inside_a_protected_name__does_not_divide_the_description():
    # DISA ships four benchmark titles containing a separator, three of them one sibling
    # family. Splitting 'System Display and Search Facility' in half hands fragment one a
    # tie across every sibling and loses the word that tells them apart.
    protected = frozenset({("display", "search")})
    assert _split("zOS IBM System Display and Search Facility for RACF", protected) == [
        "zOS IBM System Display and Search Facility for RACF"
    ]


def test_split__a_protected_name_beside_a_second_product__still_divides_at_the_other_separator():
    # The protection is on the SEPARATOR, not on the phrase. Protecting the phrase would
    # merge this into one fragment and lose the second product entirely.
    protected = frozenset({("security", "development")})
    assert _split("Application Security and Development and RHEL 9", protected) == [
        "Application Security and Development",
        "RHEL 9",
    ]


def test_split__a_caller_spelling_that_omits_the_parenthetical__is_still_protected():
    # Why the rule reads the words BRACKETING the separator rather than matching the title.
    # DISA writes 'z/OS IBM System Display and Search Facility (SDSF) for RACF'; a caller
    # writes it without the slash and without the parenthetical, so a substring test against
    # the title never matches and the description splits exactly as it does today.
    protected = frozenset({("display", "search")})
    assert len(_split("zOS IBM System Display and Search Facility for RACF", protected)) == 1
    assert len(_split("z/OS IBM System Display and Search Facility (SDSF) for RACF", protected)) == 1


def test_split__two_unrelated_products__is_unchanged_by_protection():
    protected = frozenset({("display", "search"), ("security", "development")})
    assert _split("RHEL 9 and Windows Server 2022", protected) == ["RHEL 9", "Windows Server 2022"]
    assert _split("RHEL 7, Windows Server 2025", protected) == ["RHEL 7", "Windows Server 2025"]


def test_straddling_pairs__a_title_containing_a_separator__yields_its_bracketing_words():
    stigs = [
        {"title": "z/OS IBM System Display and Search Facility (SDSF) for RACF"},
        {"title": "Application Security and Development Security Technical Implementation Guide"},
        {"title": "Red Hat Enterprise Linux 9"},
        # A separator with nothing before it: _WORD_BEFORE_SEPARATOR finds no match, so this
        # contributes no pair. Covers the branch where a bracketing word is missing.
        {"title": "and Foo Bar"},
    ]
    assert _straddling_pairs(stigs) == frozenset({("display", "search"), ("security", "development")})


def test_split__called_with_no_protected_set__still_divides_a_real_protected_pair():
    # Pins that _split's own default is empty, not some non-empty stand-in for the corpus set.
    # resolve() now always passes the corpus's straddling pairs explicitly, so nothing else in
    # the suite calls _split with a single argument on a phrase whose bracketing words are a
    # real protected pair; without this test a default that quietly grew non-empty would merge
    # this fragment and ship silently.
    assert len(_split("zOS IBM System Display and Search Facility for RACF")) == 2


def test_resolve__a_name_containing_a_separator__scopes_only_the_sibling_the_caller_named(
    splittable_name_kb,
):
    # Why separator protection exists. Split, the fragment holding 'Zzsystem Display'
    # names none of the three discriminators and ties all of them, so every sibling comes back
    # confident and _resolve_scope auto-scopes a caller who named ONE product to THREE
    # benchmarks. Protected, only the named sibling is confident.
    hits = resolve(splittable_name_kb, "Zzsystem Display and Search Zzfacility for Zzbeta", limit=5)
    assert hits[0]["stig_id"] == "SIB_ZZBETA_STIG"
    confident = [hit["stig_id"] for hit in hits if hit["high_confidence"]]
    assert confident == ["SIB_ZZBETA_STIG"]


def test_resolve__ordinary_english_matching_a_protected_pair__pins_the_accepted_empty_scope_loss(
    unrelated_straddling_kb,
):
    """Pins an ACCEPTED COST, not desired behavior.

    The protection is keyed on the bracketing WORDS, not on which product is described, so a
    description that writes ordinary English matching a protected pair after an unrelated
    product name is left undivided too, and the merged fragment carries tokens from both the
    named product and the coincidentally-matched benchmark, clearing the confidence gate for
    neither. Both halves are asserted, not just the loss: without the bare-description half a
    protection bug that emptied EVERY scope, merged or not, would pass this test too.

    Shipped with this loss known and accepted rather than fixed. A change that makes this test
    pass differently is a change to that decision, not a bug fix, and needs a fresh decision
    before it is made.
    """
    bare = resolve(unrelated_straddling_kb, "Zzapache Server 2.4")
    assert any(hit["high_confidence"] for hit in bare)

    merged = resolve(unrelated_straddling_kb, "Zzapache Server 2.4 security and development environment")
    assert merged  # candidates exist; the loss is that none of them clear the gate, not that nothing matched
    assert not any(hit["high_confidence"] for hit in merged)


def test_build_corpus__the_straddling_pairs__are_frozen(wide_kb):
    # Everything the connection cache holds is immutable, because it lives for the life of the
    # connection and one in-place write would change every later answer on it.
    *_rest, straddling = _corpus(open_db_for_test(wide_kb))
    assert isinstance(straddling, frozenset)
    with pytest.raises(AttributeError):
        straddling.add(("zz", "zz"))
