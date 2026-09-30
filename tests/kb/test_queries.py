import sqlite3
from contextlib import closing
from pathlib import Path

from stig_mcp.ingest.orchestrator import IngestSources, _keywords, build_kb
from stig_mcp.kb import queries
from stig_mcp.kb.db import create_db
from tests.conftest import discovered, open_db_for_test

FIX = Path(__file__).parent.parent / "fixtures"


def test_effective_controls__override_suppresses_ctid_pair__pair_absent(kb_path):
    conn = open_db_for_test(kb_path)
    controls = queries.effective_controls(conn, "T1078")
    by_id = {c["control_id"]: c for c in controls}
    assert "AC-2" in by_id  # ctid, kept
    assert "AC-6" in by_id  # override add
    assert "AC-8" not in by_id  # override suppress (tombstone)
    assert by_id["AC-2"]["source"] == "ctid"
    assert by_id["AC-6"]["source"] == "override"


def test_technique_control__a_tombstoned_pair__never_reaches_storage(kb_path):
    # This is the invariant that licenses effective_controls' query shape. Suppression is
    # resolved in _effective_pairs at ingest, which SKIPS a tombstoned pair rather than
    # writing it, and the only INSERT into technique_control hardcodes suppressed = 0, so the
    # query needs no NOT EXISTS against tombstones. If a future change starts storing
    # tombstones, this test fails first and names the reason.
    conn = open_db_for_test(kb_path)
    stored = conn.execute("SELECT COUNT(*) FROM technique_control WHERE suppressed != 0").fetchone()[0]
    tombstoned = conn.execute(
        "SELECT COUNT(*) FROM technique_control WHERE technique_id = 'T1078' AND control_id = 'AC-8'"
    ).fetchone()[0]
    assert stored == 0
    assert tombstoned == 0


def test_findings_for_control__cci_join__finds_the_rule_whose_details_carry_its_fix(kb_path):
    conn = open_db_for_test(kb_path)
    findings = queries.findings_for_control(conn, "AC-2(1)", [("RHEL_9_STIG", "1")])
    assert findings[0]["severity"]["cat"] == "I"
    details = queries.finding_details(conn, [f["rule_id"] for f in findings])
    assert any("automated account management" in d["fix_text"] for d in details)


def test_findings_for_control__rules_with_differing_cci_sets__each_carries_its_own(cci_batch_kb):
    # The CCI lists are fetched in one batched query rather than one per finding, so the
    # mapping from rule to CCIs is built in Python instead of by the database. That is where
    # a batching bug lives: a union over all findings, a pairing by result order, or a
    # grouping keyed on the CCI rather than the rule. This fixture separates all three,
    # because A_RULE_1 holds two CCIs and A_RULE_3 holds one of that pair and nothing else.
    # An ordered LIST, not a dict keyed on rule_id: a dict collapses the duplicate rows a
    # two-CCI rule produces without DISTINCT, so only the list form pins DISTINCT.
    findings = queries.findings_for_control(cci_batch_kb, "AC-3", [("A_STIG", "1"), ("B_STIG", "1")])
    assert [(f["rule_id"], f["ccis"]) for f in findings] == [
        ("A_RULE_1", ["CCI-000100", "CCI-000300"]),
        ("A_RULE_2", ["CCI-000200"]),
        ("A_RULE_3", ["CCI-000100"]),
        ("B_RULE_1", ["CCI-000200", "CCI-000300"]),
        ("B_RULE_2", ["CCI-000300"]),
    ]


def test_findings_for_control__more_findings__does_not_cost_more_queries(cci_batch_kb):
    # The N+1: one CCI query per finding. Comparing two scopes alone is not enough, because it
    # passes vacuously whenever the two yield the SAME number of findings. So the finding
    # counts are asserted here rather than delegated to the test above, and the statement
    # total is pinned outright. Unbatched, these read 4 and 6.
    def measure(scope):
        seen = []
        cci_batch_kb.set_trace_callback(seen.append)
        try:
            findings = queries.findings_for_control(cci_batch_kb, "AC-3", scope)
        finally:
            cci_batch_kb.set_trace_callback(None)
        return len(findings), len(seen)

    assert measure([("A_STIG", "1")]) == (3, 2)
    assert measure([("A_STIG", "1"), ("B_STIG", "1")]) == (5, 2)


def test_ccis_by_rule__real_rules_on_both_sides_of_a_chunk_boundary__none_lost_or_doubled(cci_batch_kb):
    # Two properties in one test: the parameter ceiling and chunk-boundary correctness.
    #
    # The ceiling: binding one parameter per rule imposes a limit. An interpreter linked
    # against SQLite below 3.32 defaults SQLITE_LIMIT_VARIABLE_NUMBER to 999, and CM-6
    # returns 3721 rules on the real knowledge base. setlimit reproduces that ceiling on any
    # build, and unchunked this raises rather than failing an assertion.
    #
    # The correctness: WHERE the real rules sit is the whole point. A CCI-bearing rule only
    # at the end of the input observes nothing but the last chunk. So a rule sits at index 0,
    # one at the last index of the first chunk, one at the first index of the second, and one
    # at the tail, and A_RULE_1 repeats past the boundary to pin the dedupe. Dropping the
    # dedupe, an off-by-one chunk slice, overlapping chunk ranges, or resetting the
    # accumulator inside the loop each loses or doubles CCIs here. Positions are derived from
    # _RULE_CHUNK so they hold if it changes.
    chunk = queries._RULE_CHUNK
    filler = [f"BULK_RULE_{i}" for i in range(2500)]
    rule_ids = [
        "A_RULE_1",
        *filler[: chunk - 2],
        "A_RULE_2",
        "A_RULE_3",
        *filler[chunk - 2 :],
        "B_RULE_1",
        "A_RULE_1",
    ]
    restore = cci_batch_kb.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
    try:
        assert queries._ccis_by_rule(cci_batch_kb, rule_ids) == {
            "A_RULE_1": ["CCI-000100", "CCI-000300"],
            "A_RULE_2": ["CCI-000200"],
            "A_RULE_3": ["CCI-000100"],
            "B_RULE_1": ["CCI-000200", "CCI-000300"],
        }
    finally:
        cci_batch_kb.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, restore)


def test_findings_for_control__no_stigs__returns_empty(kb_path):
    conn = open_db_for_test(kb_path)
    assert queries.findings_for_control(conn, "AC-2(1)", []) == []


def test_findings_for_control__scope_names_one_version__excludes_the_other(tmp_path):
    # RHEL_9_STIG exists at majors 1 and 2 in this KB. Scoping to major 2 must not return
    # major 1's rules: two majors of one benchmark carry different remediations, and
    # returning both hands the caller contradictory fix text.
    out = tmp_path / "kb.sqlite"
    build_kb(
        IngestSources(
            benchmarks=[discovered(FIX / "rhel9_xccdf.xml"), discovered(FIX / "rhel9_v2_xccdf.xml")],
            cci_path=FIX / "cci_list.xml",
            attack_path=FIX / "attack_bundle.json",
            ctid_path=FIX / "ctid_mappings.csv",
            overrides_path=FIX / "overrides.yaml",
            catalog_path=FIX / "oscal_catalog.json",
        ),
        out,
    )
    conn = open_db_for_test(out)
    both = queries.findings_for_control(conn, "AC-2(1)", [("RHEL_9_STIG", "1"), ("RHEL_9_STIG", "2")])
    only_v2 = queries.findings_for_control(conn, "AC-2(1)", [("RHEL_9_STIG", "2")])
    assert {f["stig_version"] for f in both} == {"1", "2"}
    assert {f["stig_version"] for f in only_v2} == {"2"}
    assert len(only_v2) < len(both)


def test_search_techniques__name_substring__finds_technique(kb_path):
    conn = open_db_for_test(kb_path)
    hits = queries.search_techniques(conn, "valid accounts")
    assert hits and hits[0]["technique_id"] == "T1078"


def test_resolve_actor__by_alias__returns_actor(kb_path):
    conn = open_db_for_test(kb_path)
    (actor,) = queries.resolve_actor(conn, "Cozy Bear").groups
    assert actor["id"] == "G0016"


def test_resolve_actor__aliases_from_a_comma_separated_list__are_returned_stripped(kb_conn):
    # attack_bundle.json's G0016 (APT29, aliases APT29/Cozy Bear) is real ingest output, but
    # orchestrator.py joins aliases with a bare comma, so this particular row carries nothing to
    # strip; it pins the shape on real data without proving the strip fires. The second test below
    # hand-inserts a padded row to exercise that.
    (actor,) = queries.resolve_actor(kb_conn, "APT29").groups
    assert actor["aliases"] and all(a == a.strip() for a in actor["aliases"])
    assert actor["aliases"] == ["APT29", "Cozy Bear"]


def test_resolve_actor__a_padded_alias_list__strips_each_alias(tmp_path):
    # Hand-inserted rather than built through build_kb, following _acronym_only_kb's technique in
    # tests/resolver/test_version_coverage.py: no real ingest source pads its aliases (they are
    # joined with a bare comma), so only a hand-inserted row exercises the strip.
    db = tmp_path / "padded_actor.sqlite"
    with closing(create_db(db)) as conn:
        conn.execute(
            "INSERT INTO actors (actor_id, name, aliases) VALUES (?, ?, ?)",
            ("G0000", "Padded Group", " Padded Group , Alt Name ,"),
        )
        conn.commit()
        (actor,) = queries.resolve_actor(conn, "Padded Group").groups
    assert actor["aliases"] == ["Padded Group", "Alt Name"]


def test_techniques_for_actor__known_actor__lists_techniques(kb_path):
    conn = open_db_for_test(kb_path)
    techniques = queries.techniques_for_actor(conn, "G0016")
    assert {t["technique_id"] for t in techniques} == {"T1078"}


def test_effective_controls__with_catalog__populates_name_and_family(kb_path):
    conn = open_db_for_test(kb_path)
    by_id = {c["control_id"]: c for c in queries.effective_controls(conn, "T1078")}
    assert by_id["AC-2"]["name"] == "Account Management"
    assert by_id["AC-2"]["family"] == "Access Control"
    assert by_id["AC-6"]["name"] == "Least Privilege"


def test_finding_details__any_finding__carries_its_release_and_origin(kb_conn):
    findings = queries.findings_for_control(kb_conn, "AC-2", [("TEST_STIG", "1")])
    (detail, *_) = queries.finding_details(kb_conn, [findings[0]["rule_id"]])
    assert detail["stig_release"] == "V1R1"
    assert detail["origin"] == "library"


def test_list_stigs__any_row__carries_release_and_status(kb_conn):
    row = queries.list_stigs(kb_conn)[0]
    assert set(row) >= {
        "stig_id",
        "title",
        "version",
        "release_label",
        "release_info",
        "origin",
        "xccdf_status",
        "xccdf_status_date",
    }


def test_source_versions__a_built_kb__reports_every_ingested_source(kb_conn):
    meta = queries.source_versions(kb_conn)
    assert "attack" in meta and "ctid" in meta
    assert set(meta["attack"]) == {"version", "artifact", "ingested_at"}


def test_library_populated__library_origin_benchmark_present__true(kb_conn):
    assert queries.library_populated(kb_conn) is True


def test_library_populated__no_library_origin_benchmark__false(no_library_kb):
    assert queries.library_populated(no_library_kb) is False


def test_library_populated__library_artifact_cited_but_contributed_nothing__false(broken_library_kb):
    # The stig_library ingest_meta row exists here (classify() found the zip), but no
    # stigs row has origin='library': the case library_populated exists to distinguish
    # from a healthy build, where the meta row's presence and this would agree.
    assert queries.library_populated(broken_library_kb) is False


def test_stigs_for_resolver__includes_keywords_from_stig_id(kb_path):
    conn = open_db_for_test(kb_path)
    rhel = next(s for s in queries.stigs_for_resolver(conn) if s["stig_id"] == "RHEL_9_STIG")
    assert "product_keywords" in rhel
    assert "rhel" in rhel["product_keywords"]  # folded in from the benchmark id


def test_list_stigs__no_filter__returns_all(kb_path):
    conn = open_db_for_test(kb_path)
    stigs = queries.list_stigs(conn)
    assert any(s["stig_id"] == "RHEL_9_STIG" for s in stigs)


def test_list_stigs__filter_matches_stig_id_absent_from_title__returns_benchmark(kb_path):
    conn = open_db_for_test(kb_path)
    # RHEL_9_STIG is titled "Red Hat Enterprise Linux 9 ...", so "RHEL" appears in the
    # benchmark id and nowhere in the prose title. A caller handed that id by
    # resolve_system must be able to filter on it.
    stigs = queries.list_stigs(conn, filter="RHEL")
    assert [s["stig_id"] for s in stigs] == ["RHEL_9_STIG"]


def test_list_stigs__filter_is_a_full_benchmark_id__returns_that_benchmark(kb_path):
    conn = open_db_for_test(kb_path)
    # Underscore is a single-character LIKE wildcard, so this term also matches the
    # space-separated product_keywords. It therefore pins the round trip a caller
    # makes (resolve_system id -> list_stigs) without isolating one SQL clause.
    stigs = queries.list_stigs(conn, filter="MS_Windows_Server_2022")
    assert [s["stig_id"] for s in stigs] == ["MS_Windows_Server_2022_STIG"]


def test_list_stigs__filter_is_a_space_separated_product__returns_benchmark(kb_path):
    conn = open_db_for_test(kb_path)
    # "rhel 9" appears in neither the title ("Red Hat Enterprise Linux 9 ...") nor the
    # underscored id, only in product_keywords, which folds the id's separators to
    # spaces. This is the clause-isolating case for keywords.
    stigs = queries.list_stigs(conn, filter="RHEL 9")
    assert [s["stig_id"] for s in stigs] == ["RHEL_9_STIG"]


def test_list_stigs__filter_matches_title__still_returns_benchmark(kb_path):
    conn = open_db_for_test(kb_path)
    stigs = queries.list_stigs(conn, filter="Red Hat")
    assert [s["stig_id"] for s in stigs] == ["RHEL_9_STIG"]


def test_list_stigs__filter_matches_nothing__returns_empty(kb_path):
    conn = open_db_for_test(kb_path)
    assert queries.list_stigs(conn, filter="no-such-product-anywhere") == []


def test_list_stigs__filter_is_a_hyphenated_benchmark_id__returns_benchmark(tmp_path):
    # product_keywords folds separators to spaces, so a hyphenated id is the only filter a
    # literal LIKE can satisfy through the stig_id clause alone. The shared fixture KB has no
    # hyphenated id, so this builds a minimal one rather than reshaping fixtures other tests count.
    stig_id = "Apple_iOS-iPadOS_18_STIG"
    title = "Apple iOS/iPadOS 18 Security Technical Implementation Guide"
    db = tmp_path / "kb.sqlite"
    conn = create_db(db)
    conn.execute(
        "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        # Derive keywords through the ingest helper so the row keeps the shape the ETL
        # writes, rather than a hand-written string that could drift from it.
        (stig_id, "1", title, _keywords(title, stig_id), "loose", "test fixture"),
    )
    conn.commit()
    conn.close()

    conn = open_db_for_test(db)
    assert [s["stig_id"] for s in queries.list_stigs(conn, filter="iOS-iPadOS")] == ["Apple_iOS-iPadOS_18_STIG"]


def test_stigs_by_ids__known_ids__returns_full_rows_in_a_single_query(kb_path):
    conn = open_db_for_test(kb_path)
    rows = queries.stigs_by_ids(conn, ["RHEL_9_STIG", "MS_Windows_Server_2022_STIG"])
    assert [r["stig_id"] for r in rows] == ["MS_Windows_Server_2022_STIG", "RHEL_9_STIG"]
    assert all(r["title"] and r["version"] for r in rows)


def test_stigs_by_ids__unknown_id__returns_nothing_for_it(kb_path):
    conn = open_db_for_test(kb_path)
    assert queries.stigs_by_ids(conn, ["NOPE_STIG"]) == []


def test_stigs_by_ids__empty_id_list__returns_empty_without_querying(kb_path):
    conn = open_db_for_test(kb_path)
    assert queries.stigs_by_ids(conn, []) == []


def test_revocation__revoked_id__returns_its_replacement(kb_path):
    conn = open_db_for_test(kb_path)
    moved = queries.revocation(conn, "T8001")
    assert moved["replacement_id"] == "T9000"
    assert moved["revoked_name"] == "Old One Hop"


def test_revocation__live_technique_id__returns_none(kb_path):
    conn = open_db_for_test(kb_path)
    assert queries.revocation(conn, "T1078") is None


def test_search_techniques__revoked_id__returns_the_replacement_marked_as_a_redirect(kb_path):
    conn = open_db_for_test(kb_path)
    hits = queries.search_techniques(conn, "T8001")
    assert [h["technique_id"] for h in hits] == ["T9000"]
    assert hits[0]["redirected_from"] == "T8001"


def test_search_techniques__revoked_name__returns_the_replacement(kb_path):
    conn = open_db_for_test(kb_path)
    hits = queries.search_techniques(conn, "Old One Hop")
    assert [h["technique_id"] for h in hits] == ["T9000"]


def test_search_techniques__live_match__reports_no_redirect(kb_path):
    conn = open_db_for_test(kb_path)
    hits = queries.search_techniques(conn, "valid accounts")
    assert hits[0]["technique_id"] == "T1078"
    assert hits[0]["redirected_from"] is None


def test_search_techniques__matches_live_and_revoked__keeps_only_the_direct_hit(kb_path):
    # The query matches T9000's own name AND revoked T8003's name, and T8003 resolves to
    # T9000, so both branches of the union produce the same technique. The direct hit has
    # to win and appear exactly once, or a caller sees the same technique twice.
    conn = open_db_for_test(kb_path)
    hits = queries.search_techniques(conn, "Replacement Technique")
    assert [h["technique_id"] for h in hits] == ["T9000"]
    assert hits[0]["redirected_from"] is None
    assert hits[0]["score"] == 100


def test_search_techniques__two_revoked_ids_redirect_to_one_technique__reports_the_lowest(kb_path):
    # "Old One Hop" (T8001) and "Old Chain Start" (T8002) both resolve to T9000 and score
    # the same, so without a tiebreak the reported redirected_from would follow whatever
    # order SQLite happened to produce.
    conn = open_db_for_test(kb_path)
    hits = queries.search_techniques(conn, "old")
    assert [h["technique_id"] for h in hits] == ["T9000"]
    assert hits[0]["redirected_from"] == "T8001"


def test_search_techniques__limit__applies_after_redirects_are_merged(kb_path):
    conn = open_db_for_test(kb_path)
    assert len(queries.search_techniques(conn, "T8001", limit=1)) == 1
