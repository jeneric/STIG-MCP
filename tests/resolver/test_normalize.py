import pytest

from stig_mcp.resolver.normalize import (
    _STOP_TOKENS,
    _SYNONYMS,
    _VERSION_RE,
    _WORD_RE,
    Tokens,
    expansion_of,
    glued_versions,
    normalize,
)


def test_normalize__redhat_variant__expands_to_red_hat_tokens():
    product, version, _ = normalize("RedHat Linux Server 9")
    assert {"red", "hat", "linux", "server"} <= product
    assert version == {"9"}


def test_normalize__rhel_acronym__expands_to_full_product():
    product, _, _ = normalize("RHEL 9")
    assert {"red", "hat", "enterprise", "linux"} <= product


def test_normalize__boilerplate__is_stripped():
    product, _, _ = normalize("Microsoft Windows 11 Security Technical Implementation Guide")
    assert product == {"microsoft", "windows"}
    assert "security" not in product and "guide" not in product


def test_normalize__year_and_release__classified_as_version():
    _, version, _ = normalize("Windows Server 2022 V1R3")
    assert "2022" in version
    assert "v1r3" in version


def test_normalize__a_digit_following_a_role_phrase_head__is_a_product_token():
    toks = normalize("Dell OS10 Switch Layer 2 Switch")
    assert "2" in toks.product
    assert toks.version == frozenset()


def test_normalize__a_digit_not_following_a_head__stays_a_version():
    toks = normalize("Oracle Linux 9")
    assert toks.version == {"9"}


def test_normalize__a_digit_following_the_tier_head__is_a_product_token():
    # A separate head from "layer": VMW_NSX-T_T1_Gateway_FW_STIG's title writes "Tier 1", the
    # gateway tier rather than a release.
    toks = normalize("VMware NSX-T Tier 1 Gateway Firewall")
    assert "1" in toks.product
    assert toks.version == frozenset()


def test_normalize__a_digit_following_the_level_head__is_a_product_token():
    # A third head, distinct from "layer" and "tier": Akamai_KSD_Service_IL2_ALG_STIG's title
    # writes "Impact Level 2", the impact level rather than a release. `_PHRASE_HEADS` is data,
    # not a branch, so a pin on one member proves nothing about another; this pins "level"
    # against the real corpus string that would silently reclassify if it were dropped.
    toks = normalize("Akamai KSD Service Impact Level 2 ALG")
    assert "2" in toks.product
    assert toks.version == frozenset()


def test_normalize__a_head_then_stop_token_then_digit__keeps_the_version():
    # Adjacency is strict: an intervening token breaks it, and the stop token is
    # still the previous token for adjacency purposes.
    toks = normalize("Application Layer Security 2022")
    assert "2022" in toks.version


# Exact equality, not a subset. A subset assertion accepts any superset, so
# "sol": "solaris windows linux server" would pass one while quietly injecting three
# generic tokens into every query containing a standalone "sol". These sets are the tokens
# that SURVIVE normalize, which is why "security" is absent from the "asa" and "asd" rows:
# it is a stop token and is dropped after expansion.
#
# Which benchmark each expansion is meant to reach is not asserted here, because that needs
# a knowledge base. It is pinned end to end for "sym" in test_resolver.py, and for the rest
# by measurement against the real knowledge base.
@pytest.mark.parametrize(
    ("acronym", "expected_tokens"),
    [
        ("HPE", {"hpe", "hewlett", "packard", "enterprise"}),
        ("WS1", {"ws1", "workspace", "one"}),
        ("KPE", {"kpe", "knox", "platform", "for", "enterprise"}),
        ("ASA", {"asa", "adaptive", "appliance"}),
        ("ACI", {"aci", "application", "centric", "infrastructure"}),
        ("SEL", {"sel", "schweitzer", "engineering", "laboratories"}),
        ("ISE", {"ise", "identity", "services", "engine"}),
        ("RACF", {"racf", "resource", "access", "control", "facility"}),
        ("TSS", {"tss", "top", "secret", "service"}),
        ("EPMM", {"epmm", "endpoint", "manager", "mobile"}),
        ("MDB", {"mdb", "mongodb"}),
        ("SOL", {"sol", "solaris"}),
        ("SYM", {"sym", "symantec"}),
        ("NTX", {"ntx", "nutanix"}),
        ("PGSQL", {"pgsql", "postgres"}),
        ("ASD", {"asd", "application", "development"}),
    ],
)
def test_normalize__disa_filename_acronym__expands_to_exactly_the_product_wording(acronym, expected_tokens):
    product, version, _ = normalize(acronym)
    assert product == expected_tokens
    assert version == set()


# Functional acronyms name a role rather than a product. Expanding them would put
# "operating system" and "database" into more than half the corpus and flatten the
# product-weighted IDF the resolver's precision depends on. Asserted behaviorally rather
# than as dict membership so it still holds if expansion is ever reimplemented.
@pytest.mark.parametrize(
    "functional",
    ["os", "db", "sql", "lan", "vpn", "dns", "api", "mdm", "ndm", "alg", "gpos", "wlan"],
)
def test_normalize__functional_acronym__passes_through_unexpanded(functional):
    assert normalize(functional) == Tokens(frozenset({functional}), frozenset(), frozenset())


# Deliberately absent from the table: "hp" is a strict subset of "hpe" and would evict every
# HP FlexFabric benchmark from a bare "HP" query in favor of HPE storage arrays, while "tmos"
# and "eos" would put "operating system" into the corpus and capture the query "operating
# system" away from TOSS and Tanium. All three do so at high confidence, so each would
# auto-scope a confidently wrong answer.
@pytest.mark.parametrize("withdrawn", ["hp", "tmos", "eos"])
def test_normalize__acronym_withdrawn_for_capturing_generic_queries__stays_unexpanded(withdrawn):
    assert normalize(withdrawn) == Tokens(frozenset({withdrawn}), frozenset(), frozenset())


# Exact equality on both sets, because the whole point is that the version is ADDED without the
# glued token leaving the product set. A subset assertion on `product` would accept the partition
# that drops `v9`, and `v9` is rare and heavily IDF-weighted, so partitioning it cuts this very
# query's score against its own benchmark. The loss is in `score`'s product term, not in
# is_high_confidence, which tests a union and is satisfied either way.
def test_glued_versions__a_v_prefixed_token__yields_the_digits():
    product, version, _ = normalize("MarkLogic Server v9")
    assert product == {"marklogic", "server", "v9"}
    assert version == set(), "normalize itself must never read it: that channel feeds scoring"
    assert glued_versions(product) == {"9"}


# The separation, and the test that protects it. A version token from `normalize` reaches
# build_idf, score and is_high_confidence. A glued version there would make the resolver answer
# `Windows 11` with a Postgres STIG, because `EDB Postgres Advanced Server v11 on Windows` would
# gain version 11 while already holding `windows`, and would tie Microsoft_Windows_11_STIG at 100.0
# AND high confidence.
# `glued_versions` is a separate function precisely so this cannot happen by editing one line.
@pytest.mark.parametrize("text", ["MarkLogic Server v9", "Oracle Database 19c", "EDB Postgres v11 on Windows"])
def test_normalize__a_glued_version__never_enters_the_token_sets_that_feed_scoring(text):
    _product, version, _ = normalize(text)
    assert version == set()


def test_normalize__a_dotted_version_whose_major_carries_a_v__yields_both_components():
    # The IBM DB2 V10.5 LUW shape. _WORD_RE splits this into 'v10' and '5', so without the glued
    # rule the version set holds only the minor and the classifier judges coverage on a 5 that
    # nothing holds.
    product, version, _ = normalize("IBM DB2 V10.5 LUW")
    assert version == {"5"}, "only the minor survives tokenizing"
    assert version | glued_versions(product) == {"10", "5"}


def test_glued_versions__a_curated_letter_suffixed_token__yields_the_digits():
    product, version, _ = normalize("Oracle Database 19c")
    assert version == set()
    assert "19c" in product
    assert glued_versions(product) == {"19"}


# The counterexamples that decide the rule, and the reason it is curated rather than
# morphological. Over the real 387-benchmark knowledge base exactly four tokens are shaped
# <digits><letters> and only `19c` is a version, so `^\d+[a-z]+$` would be right one time in four:
# it reads SEL-2740S's model number as 2740 and HPE 3PAR's line as 3. Arista's `4-2x` is the fourth
# and has its own test below, because its title also carries a legitimate bare version.
# `Omnissa WS1 UEM` is deliberately NOT in this list: `ws1` expands to "workspace one" before
# tokenizing, so no digit token ever reaches the rule and the case could not fail under any
# mutation of it.
@pytest.mark.parametrize(
    "named_digit",
    ["SEL-2740S NDM", "HPE 3PAR SSMC", "F5 BIG-IP TMOS", "Dell OS10 Switch"],
)
def test_glued_versions__digits_belonging_to_a_product_name__yield_nothing(named_digit):
    product, version, _ = normalize(named_digit)
    assert version | glued_versions(product) == set()


def test_normalize__a_versions_minor_glued_to_a_letter__does_not_become_a_major():
    # Arista MLS EOS 4-2x, the fourth <digits><letters> token in the corpus and the one that is
    # neither a version nor a name: `2x` is the MINOR of 4.2x. A morphological rule would read it as
    # version 2, a major Arista does not have, and coverage would then be judged against it. Exact
    # equality, so only the bare 4 survives.
    product, version, _ = normalize("Arista MLS EOS 4-2x L2S")
    assert version | glued_versions(product) == {"4"}


def test_normalize__a_stig_release_token__does_not_also_yield_its_major():
    # V1R3 is a STIG release, not a product version, and _VERSION_RE already classes it whole.
    # Exact equality so a glued rule that also emitted the '1' of v1r3 dies here: that 1 would
    # then be a version the caller never named, judged for coverage against every benchmark.
    product, version, _ = normalize("Windows Server 2022 V1R3")
    assert version | glued_versions(product) == {"2022", "v1r3"}


def test_normalize__token_containing_a_synonym_key__is_not_rewritten():
    # Maximal-munch: "sol" expands to "solaris", but "solstice" is one token and must not
    # be touched. Pins that expansion is keyed on whole tokens rather than substrings.
    product, _, _ = normalize("Solstice")
    assert product == {"solstice"}


def test_normalize__synonym_free_text__has_empty_expanded():
    toks = normalize("Google Chrome Current Windows")
    assert toks.expanded == frozenset()


def test_normalize__an_expansion_introduced_token__is_marked_expanded():
    # Retention keeps `tss` itself in product; `expanded` marks only the phrase the key does
    # not itself write, which is why the set difference below excludes it.
    toks = normalize("IBM zOS TSS")
    assert toks.expanded == {"top", "secret", "service"}
    assert {"ibm", "zos"} <= toks.product - toks.expanded
    assert "tss" in toks.product
    assert "tss" not in toks.expanded


def test_normalize__a_word_both_written_and_expanded__is_literal():
    # `rhel` expands to a phrase containing `enterprise`; the text ALSO writes Enterprise.
    # Set difference must classify it literal.
    toks = normalize("Splunk Enterprise for RHEL")
    assert "enterprise" not in toks.expanded
    assert "enterprise" in toks.product


def test_normalize__expansion_value_stop_tokens__are_dropped_from_expanded():
    # `asa` -> "adaptive security appliance"; `security` is a stop token and must not
    # appear in ANY set, expanded included.
    toks = normalize("Cisco ASA")
    assert toks.expanded == {"adaptive", "appliance"}
    assert "security" not in toks.product


def test_normalize__returned_sets__are_frozen():
    toks = normalize("RHEL 9")
    for field in (toks.product, toks.version, toks.expanded):
        assert isinstance(field, frozenset)


def test_expansion_of__a_synonym_key__yields_its_value_tokens_minus_stop_tokens():
    # `asa` -> "adaptive security appliance"; the doc sets never hold `security`,
    # so the relation must not demand it.
    assert expansion_of("asa") == {"adaptive", "appliance"}


def test_expansion_of__an_ordinary_token__is_none():
    assert expansion_of("oracle") is None


def test_expansions_map__every_key__equals_the_derivation_from_synonyms():
    for key, phrase in _SYNONYMS.items():
        derived = frozenset(t for t in _WORD_RE.findall(phrase) if t not in _STOP_TOKENS)
        assert expansion_of(key) == derived
    assert expansion_of("not-a-key") is None


def test_synonyms_table__every_value__holds_no_version_shaped_token():
    # Rule 4 (see the _SYNONYMS comment): _satisfied is checked against dp alone in score but
    # against dp | dv in is_high_confidence, so a digit-run value would be satisfiable at one
    # call site and not the other.
    for key, phrase in _SYNONYMS.items():
        assert not any(_VERSION_RE.match(t) for t in _WORD_RE.findall(phrase)), key
