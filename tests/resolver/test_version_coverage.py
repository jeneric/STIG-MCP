import string

from stig_mcp.kb.db import create_db
from stig_mcp.resolver.resolver import (
    _coverage_per_fragment,
    _covered_versions,
    _sorted_versions,
    _unpadded_version,
    _version_coverage,
    _version_majors,
    _version_matched,
    _version_runs,
    resolve,
)
from tests.conftest import open_db_for_test

# One benchmark per id, and every id in TOKENS also appears in VERSIONS, mirroring
# how resolve() builds both maps from the same `docs` list.
TOKENS = {
    "SQL_2016": {"sql", "server", "2016"},
    "SQL_2022": {"sql", "server", "2022"},
    "CHROME": {"chrome", "google", "windows"},
    "FIREFOX": {"firefox"},
    "APACHE_2_4": {"apache", "server", "windows", "2", "4"},
    "INTUNE": {"intune", "desktop", "mobile"},
    # Two shapes whose digits are glued to a letter. `19c` is the one `glued_versions` reads, from a
    # curated entry, so its version set holds the 19 as well; `2740s` is a model number that no rule
    # can tell apart from it, so its version set stays empty while its title still writes a run.
    # No `19` here, deliberately. `resolve` builds `tokens` as `dp | dv` and only widens `versions`,
    # so a glued major is in `versions` and NOT in `tokens`. That inequality is deliberate,
    # and a fixture preserving `versions <= tokens` could not catch a regression that
    # depends on the disagreement.
    "ORACLE_19C": {"oracle", "database", "19c"},
    "SEL_2740S": {"schweitzer", "2740s", "ndm"},
    "SOLARIS_11_X86": {"solaris", "x86", "11"},
    # A version DISA itself writes zero-padded, which is where the padding arrives from.
    "UBUNTU_22_04": {"canonical", "ubuntu", "lts", "22", "04"},
}
VERSIONS = {
    "SQL_2016": {"2016"},
    "SQL_2022": {"2022"},
    "CHROME": set(),
    "FIREFOX": set(),
    "APACHE_2_4": {"2", "4"},
    "INTUNE": set(),
    "ORACLE_19C": {"19"},
    "SEL_2740S": set(),
    "SOLARIS_11_X86": {"11"},
    "UBUNTU_22_04": {"22", "04"},
}
# 'sql', 'chrome', 'firefox', 'apache', 'intune', 'windows' are distinctive at n=100; 'server' is not.
DF = {
    "sql": 2,
    "server": 40,
    "chrome": 1,
    "google": 1,
    "windows": 3,
    "firefox": 1,
    "apache": 1,
    "intune": 1,
    "desktop": 1,
    "mobile": 1,
    "2016": 1,
    "2022": 1,
    "2": 1,
    "4": 1,
    "oracle": 1,
    "database": 1,
    "19c": 1,
    "19": 1,
    "schweitzer": 1,
    "2740s": 1,
    "ndm": 1,
    "solaris": 1,
    "x86": 1,
    "11": 1,
    "86": 1,
    "canonical": 1,
    "ubuntu": 1,
    "lts": 1,
    "22": 1,
    "04": 1,
}
# Versions as their titles write them, which is what a note shows a caller. APACHE_2_4 is
# the case that matters: its two version tokens are one version, 2.4.
WRITTEN = {
    "SQL_2016": {"2016"},
    "SQL_2022": {"2022"},
    "CHROME": set(),
    "FIREFOX": set(),
    "APACHE_2_4": {"2.4"},
    "INTUNE": set(),
    "ORACLE_19C": {"19"},
    "SEL_2740S": {"2740"},
    "SOLARIS_11_X86": {"11", "86"},
    "UBUNTU_22_04": {"22.04"},
}
INDEX = {
    stig_id: {"tokens": TOKENS[stig_id], "versions": VERSIONS[stig_id], "written": WRITTEN[stig_id]}
    for stig_id in TOKENS
}
N = 100


def hits(*pairs):
    return [{"stig_id": stig_id, "score": score} for stig_id, score in pairs]


def coverage(hit_rows, qp, qv, qm):
    """qm is stated explicitly rather than defaulted to qv: they differ for every dotted
    version, which is the whole point of the majors rule, and a default would let a test
    claim to exercise a query shape no caller can actually produce."""
    return _version_coverage(hit_rows, qp, qv, qm, INDEX, DF, N)


def test_version_coverage__product_covered_but_version_is_not__reports_uncovered():
    result = coverage(hits(("SQL_2016", 80.0), ("SQL_2022", 80.0)), {"sql", "server"}, {"2019"}, {"2019"})
    assert result == {
        "verdict": "uncovered",
        "benchmarks": ["SQL_2016", "SQL_2022"],
        "covered_versions": ["2016", "2022"],
        "query_versions": ["2019"],
    }


def test_version_coverage__benchmark_carries_no_version__reports_version_agnostic():
    result = coverage(hits(("CHROME", 80.0)), {"chrome", "google"}, {"120"}, {"120"})
    assert result["verdict"] == "version-agnostic"
    assert result["benchmarks"] == ["CHROME"]
    assert result["covered_versions"] == []


def test_version_coverage__a_tier_member_covers_the_version__stays_silent():
    assert coverage(hits(("APACHE_2_4", 80.0)), {"apache", "server"}, {"2", "4"}, {"2"}) is None


def test_version_coverage__tier_mixes_versioned_and_unversioned__stays_silent():
    # The Windows 10 shape: one tier, one member with versions and one without.
    assert coverage(hits(("APACHE_2_4", 80.0), ("CHROME", 80.0)), {"windows"}, {"10"}, {"10"}) is None


def test_version_coverage__tier_member_lacks_a_distinctive_query_token__stays_silent():
    # 'windows 10 desktop': INTUNE holds 'desktop' but not 'windows', so it is not this product.
    assert coverage(hits(("INTUNE", 47.0)), {"windows", "desktop"}, {"10"}, {"10"}) is None


def test_version_coverage__query_names_no_version__stays_silent():
    assert coverage(hits(("SQL_2016", 80.0)), {"sql", "server"}, set(), set()) is None


def test_version_coverage__query_has_no_distinctive_product_token__stays_silent():
    # Bare 'server 2019': 'server' is in 40% of benchmarks, so nothing is distinctive.
    assert coverage(hits(("SQL_2016", 80.0)), {"server"}, {"2019"}, {"2019"}) is None


def test_version_coverage__no_candidates_at_all__stays_silent():
    assert coverage([], {"sql"}, {"2019"}, {"2019"}) is None


def test_version_coverage__a_lower_scoring_benchmark__is_excluded_from_the_tier():
    # FIREFOX scores lower, so it must not drag the SQL tier into a mixed verdict.
    result = coverage(hits(("SQL_2016", 80.0), ("FIREFOX", 20.0)), {"sql", "server"}, {"2019"}, {"2019"})
    assert result["verdict"] == "uncovered"
    assert result["benchmarks"] == ["SQL_2016"]


def test_sorted_versions__plain_integers__sorts_numerically_not_lexically():
    assert _sorted_versions({"10", "8", "9"}) == ["8", "9", "10"]


def test_sorted_versions__non_numeric_token__sorts_after_the_numbers():
    assert _sorted_versions({"10", "8", "x"}) == ["8", "10", "x"]


def test_version_coverage__tier_collectively_covers_the_query__stays_silent():
    # No single benchmark holds both versions, but both are present in the tier. Saying
    # "not covered" while listing those same versions as covered is a contradiction.
    # Real case: 'vmware vsphere 7 0 ... photon os 4 0', {0,4,7} against {0,4,7,8}.
    both = {"2016", "2022"}
    assert coverage(hits(("SQL_2016", 80.0), ("SQL_2022", 80.0)), {"sql", "server"}, both, both) is None


def test_sorted_versions__a_non_ascii_digit__does_not_raise():
    # str.isdigit() is True for the superscript two, but int() rejects it, so the key
    # function must not assume the two agree.
    assert _sorted_versions({"8", "²"}) == ["8", "²"]


def test_version_coverage__query_names_a_patch_level_of_a_held_major__stays_silent():
    # 'Apache 2.4.6' against the Apache 2.4 benchmark. normalize yields {2, 4, 6}, so the
    # patch level looks like a version the tier lacks; the major, 2, is held.
    assert coverage(hits(("APACHE_2_4", 80.0)), {"apache", "server"}, {"2", "4", "6"}, {"2"}) is None


def test_version_coverage__an_absent_major_with_a_minor_the_tier_holds__reports_uncovered():
    # 'Apache 3.4': the major, 3, is genuinely absent, and the minor coinciding with the
    # tier's 4 must not buy silence. This is what distinguishes the majors rule from the
    # cheaper "any query version token is held" rule, which goes silent here.
    result = coverage(hits(("APACHE_2_4", 80.0)), {"apache", "server"}, {"3", "4"}, {"3"})
    assert result["verdict"] == "uncovered"
    # 2.4, not '2, 4': the tier holds one version, and the note must not imply two.
    assert result["covered_versions"] == ["2.4"]


def test_version_coverage__a_major_the_tier_cannot_hold__stays_silent():
    # 'Windows Server 2019 R2' yields the majors {2019, 2}. Demanding the tier hold every
    # major would deny the benchmark the query just found, so any one of them is enough.
    assert coverage(hits(("SQL_2016", 80.0)), {"sql", "server"}, {"2016", "2"}, {"2016", "2"}) is None


def test_version_majors__a_dotted_version__keeps_only_the_major():
    assert _version_majors("Solaris 11.4") == {"11"}
    assert _version_majors("Ubuntu 22.04.3") == {"22"}


def test_version_majors__a_dashed_version__keeps_only_the_major():
    # DISA writes majors with a dash in benchmark ids, and callers copy that form.
    assert _version_majors("vSphere 8-0 ESXi") == {"8"}


def test_version_majors__a_plain_version__is_returned_whole():
    assert _version_majors("Microsoft SQL Server 2019") == {"2019"}


def test_version_majors__several_versions_in_one_fragment__reports_each_major():
    assert _version_majors("vcenter 7.0 photon os 4.0") == {"7", "4"}


def test_version_majors__no_digits_at_all__is_empty():
    assert _version_majors("Google Chrome Current Windows") == set()


def test_version_runs__a_dashed_version__is_written_with_a_dot():
    # DISA writes 10.0 as 10-0 in a benchmark id, and both must render identically.
    assert _version_runs("IIS 10-0 Server") == {"10.0"}
    assert _version_runs("IIS 10.0 Server") == {"10.0"}


def test_version_runs__several_versions_in_one_title__reports_each():
    assert _version_runs("Google Android 14 MDF PP 3.3 BYOAD") == {"14", "3.3"}


def test_sorted_versions__dotted_versions__sort_componentwise_not_lexically():
    assert _sorted_versions({"10.0", "7.0", "8.5"}) == ["7.0", "8.5", "10.0"]


def test_version_coverage__no_version_tokens_but_a_number_in_the_title__stays_silent():
    # 'Schweitzer 2740S NDM 9' against SEL-2740S_NDM_STIG. _VERSION_RUN_RE reads a run out of the
    # MODEL NUMBER, so the title says 2740 while no version token confirms it. The two readings
    # disagree and neither can be trusted, so silence: calling the tier "not version-specific"
    # would contradict a non-empty covered_versions in the same verdict.
    assert coverage(hits(("SEL_2740S", 80.0)), {"schweitzer", "ndm"}, {"9"}, {"9"}) is None


def test_version_coverage__a_curated_glued_version__is_reported_as_covered():
    # 'Oracle Database 12' against Oracle_Database_19c_STIG. normalize reads 19 out of '19c', so
    # the tier is version-pinned and the caller is told which version it holds rather than being
    # left to apply 19c steps to a 12c database.
    result = coverage(hits(("ORACLE_19C", 80.0)), {"oracle", "database"}, {"12"}, {"12"})
    assert result["verdict"] == "uncovered"
    assert result["covered_versions"] == ["19"]


def test_version_coverage__a_title_digit_that_is_not_a_version__is_not_named_as_covered():
    # 'Solaris 10' against Solaris_11_X86_STIG: the run regex reads 86 out of x86, and note A
    # would otherwise tell the caller this knowledge base covers Solaris 86.
    result = coverage(hits(("SOLARIS_11_X86", 80.0)), {"solaris", "x86"}, {"10"}, {"10"})
    assert result["verdict"] == "uncovered"
    assert result["covered_versions"] == ["11"]


def test_version_coverage__a_version_agnostic_verdict__never_names_a_covered_version():
    # The invariant behind the two tests above: claiming nothing in the tier is versioned
    # while listing a covered version contradicts itself.
    result = coverage(hits(("CHROME", 80.0)), {"chrome", "google"}, {"120"}, {"120"})
    assert result["verdict"] == "version-agnostic"
    assert result["covered_versions"] == []


def test_covered_versions__a_run_sharing_one_component_with_the_tokens__is_kept_whole():
    # The IBM DB2 V10.5 LUW shape: normalize glues V10 into a product token, so the tokens hold
    # only the 5 while the title writes 10.5. Requiring every component here would render
    # "covering 5", a version that does not exist. The 2 is what DB2 leaves behind.
    assert _covered_versions({"10.5", "2"}, {"5"}) == ["10.5"]


def test_covered_versions__a_run_sharing_no_component__is_dropped():
    # The Solaris_11_X86 shape: 86 comes out of x86 and is not a version.
    assert _covered_versions({"11", "86"}, {"11"}) == ["11"]


def test_covered_versions__nothing_written_agrees_with_the_tokens__falls_back_to_them():
    # A tier whose title and whose own tokens disagree on every run. Unreachable on the current
    # library, so it is asserted here rather than left to be discovered by a note that renders
    # an empty version list.
    assert _covered_versions({"9.9"}, {"7"}) == ["7"]


def test_version_runs__a_digit_glued_after_letters__is_not_read_as_a_version():
    # The 5 of F5, the 2 of ACF2, the 10 of OS10, the 1 of WS1: all product names. Reading them
    # as versions makes the classifier treat version-agnostic benchmarks as version-pinned and go
    # silent on them.
    assert _version_runs("F5 BIG-IP TMOS NDM") == set()
    assert _version_runs("IBM zOS BMC CONTROL-D for ACF2") == set()
    assert _version_runs("Dell OS10 Switch NDM") == set()
    assert _version_runs("Omnissa WS1 UEM Server") == set()


def test_version_runs__a_digit_following_a_rejected_digit__is_not_read_as_a_version():
    # The subtle half: rejecting the 1 of OS10 must not leave the 0 to match on its own, and
    # rejecting the 3 of MaaS360 must not leave 60. Only the v10 survives here.
    assert _version_runs("IBM MaaS360 with Watson v10.x MDM") == {"10"}


def test_version_runs__a_v_prefixed_version__is_read_without_the_v():
    # A lone v is the one letter that marks a version rather than a name.
    assert _version_runs("MarkLogic Server v9") == {"9"}
    assert _version_runs("IBM WebSphere Traditional V9-x") == {"9"}


def test_version_runs__a_version_standing_on_its_own__is_still_read():
    # The cases the rule must not cost: a version after whitespace stays a version.
    assert _version_runs("Oracle Database 19c") == {"19"}
    assert _version_runs("Microsoft IIS 10.0 Server") == {"10.0"}
    assert _version_runs("VMware vSphere 8-0 ESXi") == {"8.0"}


def test_version_runs__a_run_after_a_role_phrase_head__is_not_read_as_a_version():
    # QUASAR_FABRIC_L2S_STIG's title: the 2 of "Layer 2" names the phrase, not a release, so the
    # run this feeds to the "covering" note must not carry it. Space-separated head only; a
    # hyphenated form ("Tier-0") is a documented, empirically-checked-harmless gap, not this rule.
    assert _version_runs("Quasar Fabric Layer 2 Switch") == set()
    assert _version_runs("VMware NSX-T Tier 1 Gateway Firewall") == set()


def test_version_majors__a_query_naming_a_product_whose_name_holds_a_digit__keeps_that_digit():
    # The query side deliberately does NOT apply the name-digit rule. This set is only ever
    # intersected with the tier's versions to buy silence, so an extra member is free while a
    # missing one produces a false denial. See _QUERY_RUN_RE's comment for the shapes the query
    # side does read.
    assert _version_majors("F5 BIG-IP TMOS 16 NDM") == {"5", "16"}


def test_version_coverage__the_query_pads_a_held_version_with_a_zero__stays_silent():
    # 'Microsoft SQL Server 02016' against the 2016 benchmark. Compared as strings, 02016 and 2016
    # are different versions, and the note would deny a version it lists as covered in the same
    # sentence.
    assert coverage(hits(("SQL_2016", 80.0)), {"sql", "server"}, {"02016"}, {"02016"}) is None


def test_version_coverage__a_bare_query_version_against_the_tiers_padded_one__reports_uncovered():
    # Ubuntu's title writes 22.04, so the tier holds the token 04 where this caller asks for 4.
    # Unpadding runs one way, caller only, for the reason in _version_matched: the symmetric form
    # silences this correct note and auto-scopes 'Ubuntu 4' to Ubuntu 22.04.
    result = coverage(hits(("UBUNTU_22_04", 80.0)), {"canonical", "ubuntu"}, {"4"}, {"4"})
    assert result["verdict"] == "uncovered"
    assert result["covered_versions"] == ["22.04"]


def test_version_coverage__a_padded_version_the_tier_does_not_hold__still_reports_uncovered():
    # The guard against over-silencing: padding must not make every query match. 07 is 7, and 7 is
    # genuinely absent from a tier covering 2016.
    result = coverage(hits(("SQL_2016", 80.0)), {"sql", "server"}, {"07"}, {"07"})
    assert result["verdict"] == "uncovered"


def test_unpadded_version__a_zero_padded_number__is_the_same_version_as_the_bare_one():
    assert _unpadded_version("08") == _unpadded_version("8")
    assert _unpadded_version("02016") == _unpadded_version("2016")


def test_unpadded_version__all_zeroes__keeps_one_of_them():
    # Stripping alone would leave the empty string, which would then match any other all-zero
    # token AND compare equal to a missing version.
    assert _unpadded_version("00") == "0"


def test_unpadded_version__a_digit_run_too_long_for_int__is_still_keyed():
    # str(int(...)) raises above CPython's int_max_str_digits, on caller-supplied text.
    assert _unpadded_version("0" + "9" * 4301) == "9" * 4301


def test_unpadded_version__a_non_ascii_or_non_numeric_token__is_returned_unchanged():
    # An Arabic-Indic digit reaches here because qm is built from \d. Left unkeyed on purpose:
    # matching nothing errs toward speaking rather than silently equating scripts.
    assert _unpadded_version("x") == "x"
    assert _unpadded_version("\u0669") == "\u0669"


def test_sorted_versions__two_spellings_of_one_number__sort_the_same_in_either_input_order():
    # 04 and 4 compare equal numerically, so without a tiebreaker their order comes from whichever
    # the caller happened to iterate first. The input is a list rather than a set on purpose: a set
    # would make this test pass or fail on the hash seed instead of on the code.
    assert _sorted_versions(["4", "04", "12"]) == _sorted_versions(["04", "4", "12"])
    assert _sorted_versions(["4", "04", "12"]) == ["04", "4", "12"]


def test_sorted_versions__a_digit_run_too_long_for_int__sorts_without_raising():
    # int() refuses more than int_max_str_digits (4300 by default), and this list reaches the
    # numeric branch. Ordering digit strings by (width, digits) is a value compare with no ceiling.
    huge = "9" * 4301
    assert _sorted_versions([huge, "8"]) == ["8", huge]


def test_version_matched__a_padded_caller_token__matches_the_version_it_pads():
    # Padding is a caller-side spelling artifact: '08' is how an inventory tool writes 8.
    assert _version_matched({"08"}, {"8", "9"}) == {"08"}


def test_version_matched__a_bare_caller_token_against_a_padded_doc_token__does_not_match():
    # Asymmetric ON PURPOSE. Unpadding DISA's side too would make 4 and 04 one version, and
    # Canonical writes 22.04, so a caller who said 'Ubuntu 4' would be auto-scoped, confidently,
    # to Ubuntu 22.04. That is a wrong answer in the selection path, not merely a wrong note.
    assert _version_matched({"4"}, {"22", "04"}) == set()


def test_version_matched__an_exact_padded_token_on_both_sides__matches():
    # 'Ubuntu 22.04' against Canonical's own 22.04 must keep matching every token it names.
    assert _version_matched({"22", "04"}, {"22", "04"}) == {"22", "04"}


def test_resolve__a_spelled_out_synonym_naming_an_unheld_version__reports_uncovered_coverage(wide_kb):
    # End-to-end pin that a spelled-out synonym naming an unheld version gets an uncovered verdict.
    # wide_kb's RHEL doc writes every expansion word literally, so the verdict holds whichever df
    # the distinctiveness gate reads; it catches a gate change that moves it.
    hits = resolve(open_db_for_test(wide_kb), "Red Hat Enterprise Linux 8")
    assert hits[0]["version_coverage"][0]["verdict"] == "uncovered"


def test_version_coverage__query_versions__renders_the_callers_padding_unpadded(wide_kb):
    # 'RHEL 08' against a KB that only holds RHEL_9_STIG: uncovered, and query_versions must
    # render the caller's own padded token unpadded, the same rule _unpadded_version already
    # applies when matching. Unrendered, '08' would sit next to the covered '9' looking like a
    # different release than the one the caller actually typed.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 08")
    coverage = hits[0]["version_coverage"]
    assert len(coverage) == 1 and coverage[0]["query_versions"] == ["8"]


def test_version_coverage__query_versions__collapses_two_spellings_of_one_version():
    # A caller writing both '6' and '06' in one query ('RHEL 6 06') gives _version_majors both
    # spellings too, since it does no unpadding: qm carries them verbatim, same as qv. query_versions
    # must still render the pair once, not twice. This is what tells apart the render's set
    # comprehension, which unpadding forces to collapse the two shapes, from a list comprehension,
    # which would preserve both and print '6, 6'. SQL_2016 is a stand-in target; the version tokens
    # are the point, not the tier.
    result = coverage(hits(("SQL_2016", 80.0)), {"sql", "server"}, {"6", "06"}, {"6", "06"})
    assert result["verdict"] == "uncovered"
    assert result["query_versions"] == ["6"]


def _acronym_only_kb(tmp_path):
    """One benchmark that spells its product out in full, never writing the acronym `mdb`,
    plus 19 filler rows so the corpus clears the distinctiveness gate (n=20, gate 1.0).

    Hand-inserted rather than built through build_kb (as in test_corpus_cache.py's
    `test_corpus__the_index_expanded_view__holds_only_expansion_introduced_tokens` and conftest.py's
    `tie_kb`): build_kb folds a benchmark's stig_id into product_keywords, so any acronym-titled
    row it builds already carries the acronym literally and cannot pin a document holding ONLY
    the expansion.
    """
    db = tmp_path / "acronym_only.sqlite"
    conn = create_db(db)
    conn.execute(
        "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            "MONGODB_ENTERPRISE_ADVANCED_7_STIG",
            "1",
            "MongoDB Enterprise Advanced 7-x",
            "mongodb enterprise advanced 7 x",
            "loose",
            "test fixture",
        ),
    )
    for index in range(19):
        # Multi-letter and disjoint from the real row's tokens, for the same reason
        # conftest.py's _filler_benchmarks gives, and 19 fillers plus the real row is
        # exactly the n=20 threshold the distinctiveness gate needs to speak at all.
        suffix = f"Zz{string.ascii_lowercase[index]}"
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                f"FILLER_{suffix.upper()}_STIG",
                "1",
                f"Fillerware Padding Appliance {suffix}",
                f"fillerware padding appliance {suffix.lower()}",
                "loose",
                "test fixture",
            ),
        )
    conn.commit()
    conn.close()
    return open_db_for_test(db)


def test_resolve__an_acronym_query_naming_an_uncovered_version__reports_uncovered_coverage(tmp_path):
    # _version_coverage's tier held-test must go through _satisfied like is_high_confidence does,
    # not a raw subset test: the query "mdb 9" retains the literal token "mdb" beside its "mongodb"
    # expansion, and a document that only ever spells the product out holds "mongodb" but never
    # "mdb" literally. A raw subset test fails on "mdb" alone and silently drops a verdict a
    # confident query is owed. wide_kb cannot pin this shape; see _acronym_only_kb.
    hits = resolve(_acronym_only_kb(tmp_path), "mdb 9")
    assert hits[0]["stig_id"] == "MONGODB_ENTERPRISE_ADVANCED_7_STIG"
    assert hits[0]["version_coverage"] != []
    assert hits[0]["version_coverage"][0]["verdict"] == "uncovered"
    assert hits[0]["version_coverage"][0]["covered_versions"] == ["7"]


def test_resolve__a_single_fragment_query__yields_exactly_one_verdict(wide_kb):
    # A query with one fragment yields exactly one verdict, as the sole element of the list.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 8")
    coverage = hits[0]["version_coverage"]
    assert len(coverage) == 1
    assert coverage[0]["verdict"] == "uncovered"
    assert coverage[0]["fragment"] == "RHEL 8"


def test_resolve__nothing_to_report__yields_an_empty_list(wide_kb):
    # The empty case is [] and never None, so a caller can iterate without a guard. A None would
    # still be falsy, letting an `if not coverage` reader pass while `for v in coverage` crashes.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 9")
    assert hits[0]["version_coverage"] == []


def test_resolve__one_fragment_names_an_absent_version__attributes_the_verdict_to_it(wide_kb):
    # 'RHEL 8 and Windows Server 2022' merged into one candidate map cannot attribute the
    # uncovered 8 to the fragment that named it, so per-fragment verdicts are what let it speak
    # as 'RHEL 8' alone does. The Windows fragment is covered and says nothing; the RHEL fragment
    # gets the verdict and carries its own text.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 8 and Windows Server 2022")
    coverage = hits[0]["version_coverage"]
    assert [(v["fragment"], v["verdict"]) for v in coverage] == [("RHEL 8", "uncovered")]
    assert coverage[0]["covered_versions"] == ["9"]


def test_resolve__both_fragments_name_absent_versions__yields_a_verdict_for_each(wide_kb):
    # Two verdicts is a common case, not an edge: a shape that could only carry one would be
    # silent about the second product.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 8 and Google Chrome 120")
    coverage = hits[0]["version_coverage"]
    assert [(v["fragment"], v["verdict"]) for v in coverage] == [
        ("RHEL 8", "uncovered"),
        ("Google Chrome 120", "version-agnostic"),
    ]


def test_resolve__a_fragments_verdict__names_only_the_benchmarks_that_fragment_matched(wide_kb):
    # matched_benchmarks is what the note gate reads, and it must hold THIS fragment's surviving
    # candidates rather than the query's. Without the per-fragment restriction the confident
    # Windows hit would suppress the RHEL note, which is the whole defect: the two statements do
    # not contradict each other because they are about different products.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 8 and Windows Server 2022")
    coverage = hits[0]["version_coverage"]
    assert "MS_Windows_Server_2022_STIG" not in coverage[0]["matched_benchmarks"]
    assert "RHEL_9_STIG" in coverage[0]["matched_benchmarks"]


def _one_product_many_benchmarks_kb(tmp_path):
    """Five benchmarks of one product at one version, plus 115 fillers.

    The filler count is a FLOOR with margin, not a chosen number, and must not be reduced.
    `zzquartz` has df 5 because all five components carry it, and the distinctiveness gate is
    `df <= 0.05 * n`, so the corpus needs n >= 100 before a token five benchmarks share can be
    distinctive at all. 19 fillers, which is what _acronym_only_kb needs for its df-1 token,
    gives a gate of 1.2 and no verdict. 95 fillers sits exactly ON the gate (n=100, gate 5.0,
    df 5), so removing one filler would kill this test for a reason unrelated to what it pins;
    120 rows leaves a gate of 6.0 and a document of headroom. Hand-inserted for the reason
    _acronym_only_kb gives.

    Exists because NO shared fixture can exercise the matched_benchmarks narrowing: it needs a
    fragment matching more benchmarks than `limit` shows AND producing a verdict, and every
    verdict-producing query on wide_kb reaches exactly one benchmark.
    """
    db = tmp_path / "many.sqlite"
    conn = create_db(db)
    for component in ("Alpha", "Bravo", "Charlie", "Delta", "Echo"):
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                f"ZZQUARTZ_7_{component.upper()}_STIG",
                "1",
                f"Zzquartz 7 {component}",
                f"zzquartz 7 {component.lower()}",
                "loose",
                "test fixture",
            ),
        )
    for index in range(115):
        suffix = f"Yy{string.ascii_lowercase[index % 26]}{index}"
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                f"FILLER_{suffix.upper()}_STIG",
                "1",
                f"Fillerware {suffix}",
                f"fillerware {suffix.lower()}",
                "loose",
                "x",
            ),
        )
    conn.commit()
    conn.close()
    return open_db_for_test(db)


def test_resolve__a_fragment_matching_more_than_the_limit__lists_only_the_kept_benchmarks(tmp_path):
    # matched_benchmarks is a payload contract, not a mechanism: dropping the narrowing kills no
    # behavior test, because the note gate filters over rows that are already capped. It is
    # narrowed so the field stays small enough to ship on every row of the response, and this is
    # the only thing pinning that. 'Zzquartz 9' matches all five components and one is shown.
    conn = _one_product_many_benchmarks_kb(tmp_path)
    hits = resolve(conn, "Zzquartz 9", limit=1)
    coverage = hits[0]["version_coverage"]
    assert coverage[0]["verdict"] == "uncovered"
    # The tier names every benchmark the caller could use; matched_benchmarks names only the
    # one shown. The two differing is the whole point of the field.
    assert len(coverage[0]["benchmarks"]) == 5
    assert coverage[0]["matched_benchmarks"] == [hits[0]["stig_id"]]


def test_resolve__a_fragment_matching_another_fragments_confident_hit__still_reports_its_own(wide_kb):
    # The gate must judge a fragment by what IT matched confidently, not by the confidence on
    # the rows. A row's high_confidence belongs to whichever fragment won that key in the
    # merged map, and a fragment becomes a candidate for a benchmark on one shared common token
    # (_SCORE_FLOOR is 10.0), so 'RHEL 8' is a candidate for the Windows benchmark that the
    # OTHER fragment made confident. Reading the row's flag would silence the RHEL half entirely.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 8 and Windows Server 2022")
    assert any(hit["high_confidence"] for hit in hits), "the other fragment must match confidently"
    verdict = hits[0]["version_coverage"][0]
    assert verdict["fragment"] == "RHEL 8"
    assert verdict["fragment_confident"] is False


def test_resolve__the_fragment_itself_matched_confidently__is_marked_confident(wide_kb):
    # The True direction, without which the flag could be a constant False and nothing at this
    # level would notice. 'RHEL 8.9' is the canonical contradiction: an alias makes it a
    # confident RHEL_9_STIG hit at 100.0 while the classifier says 8 is not held, and the note
    # has to stay silent about a version the same call just confidently scoped. A covered query
    # would yield no verdict dict at all and could not observe the flag.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 8.9")
    verdict = hits[0]["version_coverage"][0]
    assert verdict["fragment"] == "RHEL 8.9"
    assert verdict["verdict"] == "uncovered"
    assert verdict["fragment_confident"] is True


def test_resolve__one_fragment_confident_and_one_not__flags_only_the_confident_one(wide_kb):
    # Both directions in one query, which is what makes the flag per fragment rather than per
    # query. The alias half is confident and must stay silent; the Chrome half is not and must
    # speak, in the same call.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 8.9 and Google Chrome 120")
    flags = {v["fragment"]: v["fragment_confident"] for v in hits[0]["version_coverage"]}
    assert flags == {"RHEL 8.9": True, "Google Chrome 120": False}


def _fragment(text, qp, qv, qm, rows):
    """One entry of resolve()'s fragment_candidates list, for feeding _coverage_per_fragment
    directly. `rows` is (stig_id, score, confident) triples."""
    own = {(stig_id, "1"): {"stig_id": stig_id, "score": score, "confident": conf} for stig_id, score, conf in rows}
    return (text, qp, qv, qm, own)


def test_coverage_per_fragment__a_confident_row_below_the_fragments_top_score__is_not_flagged():
    # The epsilon term in fragment_confident mirrors resolve()'s own clear, which drops confidence
    # on any row more than a tie's width below the top, so an outranked confident hit cannot
    # silence a note the caller is owed ('Cisco ACI NDM 2' is that shape).
    #
    # Fed directly rather than through a fixture: an outranked-but-confident row is a state
    # resolve() reaches only through score arithmetic no small knowledge base reproduces.
    outranked = _fragment(
        "sql 2019", {"sql", "server"}, {"2019"}, {"2019"}, [("SQL_2016", 80.0, True), ("SQL_2022", 100.0, False)]
    )
    assert _coverage_per_fragment([outranked], INDEX, DF, N)[0]["fragment_confident"] is False


def test_coverage_per_fragment__a_confident_row_tied_with_the_top__is_flagged():
    # The other side of the same comparison, so the term is pinned as a tie tolerance rather
    # than as an unconditional exclusion. Tied to within the epsilon, not exactly equal,
    # because these are summed floats and exact equality is what the epsilon exists to avoid.
    tied = _fragment(
        "sql 2019",
        {"sql", "server"},
        {"2019"},
        {"2019"},
        [("SQL_2016", 100.0 - 1e-12, True), ("SQL_2022", 100.0, False)],
    )
    assert _coverage_per_fragment([tied], INDEX, DF, N)[0]["fragment_confident"] is True


def test_resolve__the_same_fragment_written_twice__reports_it_once(wide_kb):
    # 'RHEL 8 and RHEL 8' splits into two identical fragments; they collapse to one verdict so
    # the note does not repeat a sentence.
    hits = resolve(open_db_for_test(wide_kb), "RHEL 8 and RHEL 8")
    assert [v["fragment"] for v in hits[0]["version_coverage"]] == ["RHEL 8"]
