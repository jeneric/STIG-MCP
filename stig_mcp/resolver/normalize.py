import re
from types import MappingProxyType
from typing import NamedTuple

# Curated variant -> canonical-phrase expansions, applied to query AND haystack. Small and
# high-value; each maps one token to the words it should behave like.
#
# The vendor and product entries below are curated from DISA's _STIG_File_Name_Acronym_List,
# shipped in the root of the library compilation, and each entry is checked against a built
# knowledge base before it is added. The entries serve two different needs:
# "mdb", "sol", "sym", "ntx", "pgsql" and "asd" let an acronym reach a benchmark that spells the
# product out, because DISA's acronyms live in the *published zip filename*
# (U_MDB_Enterprise_Advanced_8-x_V1R1_STIG.zip) while the resolver only ever sees the *benchmark
# id inside the archive* (MongoDB_Enterpise_Advanced_8-x_STIG). The rest do the opposite, letting
# a full product name reach a benchmark named only by its acronym.
#
# Four rules govern what does NOT belong here. The first two are about the key, the other two
# are about the value:
#
#   1. No functional acronyms as a key. OS, DB, SQL, LAN, VPN, DNS, API, MDM, NDM, ALG, GPOS and
#      WLAN name a role rather than a product. Expanding them injects "operating system" and
#      "database" into more than half the corpus, which is exactly what the product-weighted IDF
#      scoring exists to discount. "iis" is the one exception: DISA's own list classes it as
#      functional, but it names one product line and its expansion adds only "services" to the
#      corpus, since "internet" and "information" appear in no benchmark title.
#   2. No two-letter keys unless the abbreviation is unambiguous and in universal use. "ms" earns
#      it; CL, IB, AP, CA, SS, HW and RB do not, because an entry rewrites any standalone
#      occurrence of the token and a short one rewrites text it was never meant to touch. Every
#      key, "ms" included, is also kept as a literal corpus token with its own df (see
#      normalize()), and "ms" sits inside the band distinctiveness_margin reports (df 19 against a
#      gate of 19.30 on the reference build); see its first crossing condition for when one more
#      MS_* benchmark makes it common. That is accepted rather than tuned away, because the
#      literal-vs-expanded token split it rests on is also what lets a bare `MS` auto-scope.
#   3. No generic role words in the *value*, and no value that is a strict subset of another
#      entry's. "tmos" and "eos" expanding to "... operating system" would make the query
#      "operating system" auto-scope to Arista and F5 instead of TOSS and Tanium, and "hp" ->
#      "hewlett packard", a subset of "hpe" -> "hewlett packard enterprise", would evict the HP
#      FlexFabric benchmarks from a bare "HP" query in favor of HPE storage arrays, both at high
#      confidence. The acronyms resolve without those entries. Nor may a value consist entirely
#      of stop tokens: `expansion_of` would then return an empty frozenset, and an empty
#      requirement is a subset of every document's tokens, satisfying all of them.
#   4. No version-shaped token in the *value*. `_satisfied` (resolver.py) is checked against `dp`
#      alone at `score`'s call site but against `dp | dv` at `is_high_confidence`'s, so a value
#      holding a digit run (a version token by `_VERSION_RE`) would be satisfiable at one call
#      site and not the other: an inconsistency, not a curated tradeoff. Pinned by
#      test_synonyms_table__every_value__holds_no_version_shaped_token in
#      tests/resolver/test_normalize.py.
#
# Known and accepted: "hpe" and "kpe" push "enterprise" past the distinctiveness threshold, so
# roughly seven "Enterprise <version>" queries keep their correct top hit but stop auto-scoping.
# That is a convenience loss rather than a wrong answer, and no cheaper cut removes it.
#
# Distinctiveness is judged by full df, not literal document frequency: under literal df the
# expansion-inflated generic words (access, control, enterprise, facility, resource, secret,
# service, top) flip from common to distinctive, and a bare generic word like "Access" then
# auto-scopes at high confidence.
#
# Read on every normalize() call and never written, so it is a proxy rather than a dict: it lives for
# the life of the PROCESS across every connection, which is a longer reach than the per-connection
# corpus, and it sits on the QUERY side of every comparison. Writing "rhel" -> "microsoft windows"
# here answers `RHEL 9` with a Windows DNS benchmark on a connection whose own corpus is already
# frozen. `_STOP_TOKENS` below is a frozenset for the same reason.
_SYNONYMS = MappingProxyType(
    {
        "redhat": "red hat",
        "rhel": "red hat enterprise linux",
        "win": "windows",
        "ms": "microsoft",
        "iis": "internet information services",
        "hpe": "hewlett packard enterprise",
        "ws1": "workspace one",
        "kpe": "knox platform for enterprise",
        "asa": "adaptive security appliance",
        "aci": "application centric infrastructure",
        "sel": "schweitzer engineering laboratories",
        "ise": "identity services engine",
        "racf": "resource access control facility",
        "tss": "top secret service",
        "epmm": "endpoint manager mobile",
        "mdb": "mongodb",
        "sol": "solaris",
        "sym": "symantec",
        "ntx": "nutanix",
        "pgsql": "postgres",
        # Deliberately not "application security and development": "security" is a stop token and
        # would be dropped anyway, while "and" is not, and resolver._SPLIT_RE treats a standalone
        # "and" as a fragment separator.
        "asd": "application development",
    }
)

# Tokens present in ~every DISA benchmark title; no discriminating signal.
_STOP_TOKENS = frozenset({"security", "technical", "implementation", "guide", "stig", "srg", "benchmark", "manual"})

_WORD_RE = re.compile(r"[a-z0-9]+")
_VERSION_RE = re.compile(r"^\d+(?:[.-]\d+)*$|^v\d+r\d+$")

# Derived from _SYNONYMS at import: expansion_of is a lookup, not a re-derivation per call.
_EXPANSIONS = MappingProxyType(
    {key: frozenset(t for t in _WORD_RE.findall(phrase) if t not in _STOP_TOKENS) for key, phrase in _SYNONYMS.items()}
)

# A bare digit run immediately after one of these words is part of the phrase, not a version:
# "Layer 2", "Tier 1". Curated at the _SYNONYMS standard: a wrong member here reclassifies a
# real version as a product token, which is a wrong answer, so verify each candidate against the
# real corpus before adding.
_PHRASE_HEADS = frozenset({"layer", "tier", "level", "phase", "type", "zone", "class"})

# A version glued to a letter. `_WORD_RE` tokenizes on [a-z0-9]+, so `v9` and `19c` each arrive as
# ONE token and _VERSION_RE rejects both for carrying a letter; the benchmark's version set would
# then be empty and the classifier would judge coverage against a version it cannot see. `V10.5` is
# worse than empty: it splits into `v10` and `5`, leaving only the minor.
#
# No dotted form here, because a token can never contain `.` or `-` by the time this matches.
_V_PREFIXED_VERSION = re.compile(r"^v(\d+)$")
# The rest are curated one at a time, because morphology cannot decide them. Of the tokens shaped
# <digits><letters> in `title + product_keywords` (what `resolve` tokenizes), only `19c` is a
# version: `2740s` is a Schweitzer model number, `3par` is HPE's array line and `2x` (from Arista
# MLS EOS 4-2x) is a version's MINOR. So `^\d+[a-z]+$` would be right for only one of them. Oracle's
# own suffix convention (12c, 19c, 21c) is not spelled as a rule either, because `^\d+[igc]$`
# would acquire a 5G benchmark's `5g` the day DISA publishes one.
_GLUED_VERSIONS = MappingProxyType({"19c": "19"})
# Curated against the current library, and it degrades rather than breaks on any other: older
# libraries also hold `Oracle Database 12c` and `Oracle Database 11g`, which this map does not read.
# The loss is silence, never a wrong answer: a tier whose member carries no version token makes
# `all(tier_versions)` false and the classifier returns None. Add an entry when a build needs one;
# nothing tests this map against a real corpus.


class Tokens(NamedTuple):
    """normalize's result. `expanded` is the subset of product | version present ONLY
    because synonym expansion introduced it; a word the text also writes is literal."""

    product: frozenset
    version: frozenset
    expanded: frozenset


def glued_versions(product_tokens):
    """The versions readable from tokens that also carry letters: `{v9, jamf}` gives `{9}`.

    **Read by the version-coverage classifier ONLY, never by scoring.** `normalize` cannot do this
    itself, because a version token feeds `build_idf`, `score` and `is_high_confidence`, and the
    resolver would then answer `Windows 11` with a Postgres STIG:
    `EDB Postgres Advanced Server v11 on Windows` would gain version 11, its product tokens already
    hold `windows`, and it would tie `Microsoft_Windows_11_STIG` at 100.0 AND high confidence. The
    classifier needs the version to decide coverage; nothing needs it to decide selection, and the
    two must not share a channel.
    """
    found = set()
    for token in product_tokens:
        prefixed = _V_PREFIXED_VERSION.match(token)
        if prefixed:
            found.add(prefixed.group(1))
        elif token in _GLUED_VERSIONS:
            found.add(_GLUED_VERSIONS[token])
    return found


def expansion_of(token):
    """The stop-filtered tokens of a synonym key's expansion, or None for an ordinary token.
    Precomputed at import; see _EXPANSIONS.

    Stop tokens are removed because no document set holds them: `asa`'s value contains
    `security`, and a relation demanding it would never be satisfied by any document."""
    return _EXPANSIONS.get(token)


def normalize(text):
    """Lowercase, expand synonyms, tokenize, drop boilerplate, and classify the surviving
    tokens into a `Tokens(product, version, expanded)`.

    A version glued to a letter (`v9`, `19c`, and `V10.5`, which splits into `v10` and `5`) stays a
    PRODUCT token here and is deliberately not read as a version: see `glued_versions`, which the
    classifier calls separately, for why.

    `Tokens.expanded` marks the subset of product | version present only because synonym expansion
    introduced it; a word the text also writes stays classified as literal.
    """
    literal_tokens, expansion_tokens = [], []
    for token in _WORD_RE.findall(text.lower()):
        literal_tokens.append(token)
        expansion = _SYNONYMS.get(token)
        if expansion is not None:
            expansion_tokens.extend(_WORD_RE.findall(expansion))
    lp, lv = _classify(literal_tokens)
    ep, ev = _classify(expansion_tokens)
    return Tokens(
        product=frozenset(lp | ep),
        version=frozenset(lv | ev),
        expanded=frozenset((ep | ev) - (lp | lv)),
    )


def _classify(tokens):
    product, version = set(), set()
    previous = None
    for token in tokens:
        if token in _STOP_TOKENS:
            previous = token
            continue
        if _VERSION_RE.match(token) and previous not in _PHRASE_HEADS:
            version.add(token)
        else:
            product.add(token)
        previous = token
    return product, version
