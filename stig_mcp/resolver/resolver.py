import math
import os
import re
from pathlib import Path
from types import MappingProxyType
from typing import NamedTuple

import yaml

from stig_mcp import applicability
from stig_mcp.kb.queries import stigs_for_resolver
from stig_mcp.resolver.normalize import _PHRASE_HEADS, expansion_of, glued_versions, normalize

HIGH_CONFIDENCE = 80
_DISTINCTIVE_DF_RATIO = 0.05  # a token in <=5% of benchmarks is "distinctive"


class MarginBand(NamedTuple):
    n: int
    gate: float
    losing: list
    gaining: list


def distinctiveness_margin(conn, width=1):
    """Tokens within `width` documents of the distinctiveness gate, in both directions.

    Reported rather than acted on: the gate is a ratio so that what counts as distinctive
    tracks corpus growth, and a token crossing it is correct behavior. The hazard is that a
    crossing is silent, changing what the resolver confidently scopes with no code change and
    no test failure. The suite cannot catch a crossing at all, since it runs on fixtures and
    this is a property of the operator's real corpus.

    The two directions are not symmetric, and callers must not describe them as though they
    were, but neither one crosses on every next benchmark: whether a token in the band
    actually crosses depends on where inside the band its df sits, not merely on which side
    of the gate it is on. The gate moves by 0.05 for every benchmark the corpus gains or
    loses, and a token's df moves by 1 for every benchmark that starts or stops holding it.
    So there are four crossing conditions:

    - a `losing` token becomes common when one more holding benchmark arrives, if
      `df > gate - 0.95`;
    - a `gaining` token becomes distinctive when a benchmark holding it is RETIRED, if
      `df <= gate + 0.95`;
    - corpus growth alone, with nothing retired, makes a `gaining` token distinctive only if
      `df <= gate + 0.05`;
    - retiring a benchmark that does NOT hold a `losing` token makes it common if
      `df > gate - 0.05`, since df holds still while the gate drops. Writing n as `20q + r`,
      that admits an integer only at `r == 0`, where it is `df == gate` exactly.

    A token nearer the band's outer edge does not cross: at n=39, gate 1.95, a `losing` token at
    df 1 fails `1 > 1.00` and stays distinctive as df 2 against a gate of 2.00 at n=40. All four
    conditions hold under a brute-force check over n=1..2000.

    **Those four enumerate a benchmark ARRIVING or LEAVING, and this pipeline's routine event
    is neither.** `_newest_benchmarks` keys on (stig_id, major) and keeps the newest release,
    so a quarterly re-release REPLACES a row: n does not move, the gate does not move, and a
    DISA retitle moves df by one on its own. With the gate held still there is no threshold
    left to be near, and df +/- 1 crosses the WHOLE band in either direction, which is wider
    than any route above. The four conditions are what make the band's width meaningful; they
    are not a bound on how a token can cross.

    Every message here and in the callers says "benchmark", but n is the number of ROWS
    stigs_for_resolver returns, one per (stig_id, version), not the number of distinct
    benchmarks. The arithmetic above is unaffected, since n and a token's df both move per
    row, but a reader redoing it against a benchmark count is off by the difference.

    df and n come from _corpus rather than being recomputed here, and that is the whole
    reason this lives in the resolver while its callers are elsewhere. build_idf counts
    `t.product | t.version` over `title + product_keywords`, so a second implementation
    would have to reproduce that token universe exactly, and two copies of one rule drift.
    """
    _stigs, _docs, _idf, df, n, _index_by_id, _straddling = _corpus(conn)
    gate = _DISTINCTIVE_DF_RATIO * n
    return MarginBand(
        n=n,
        gate=gate,
        losing=sorted((token, count) for token, count in df.items() if gate - width < count <= gate),
        gaining=sorted((token, count) for token, count in df.items() if gate < count <= gate + width),
    )


_WEIGHT_PRODUCT = 0.8
_WEIGHT_VERSION = 0.2
_SCORE_FLOOR = 10.0
# Two scores this close are one tier: see the summed-float note in resolve().
_SCORE_TIE_EPSILON = 1e-9
_ALIASES_PATH = Path(__file__).parent / "aliases.yaml"
# Where a connection keeps the corpus derived from it: see _corpus, and CorpusCachingConnection for
# why it lives on the connection rather than in a dict keyed on the knowledge-base file.
_CORPUS_ATTR = "_stig_resolver_corpus"
# The alias table is a repository file rather than a generated one, so its own identity is a sound
# key. Bounded because tests point _ALIASES_PATH at temporary files.
_ALIASES_CACHE_MAX = 4
_ALIASES_CACHE = {}
_SPLIT_RE = re.compile(r",|\band\b", flags=re.IGNORECASE)
# The word immediately before and after a separator. `re.search` scans left to right, so each
# call is linear in the prefix up to the separator, and that prefix grows with every separator
# `_split` walks: the anchor makes ONE search cheap, it does not make the whole scan linear.
# `_split` is therefore quadratic in the number of separators. On a 200-item comma inventory it
# is a real but minority share of a whole `resolve()` call, which is why it is left alone.
_WORD_BEFORE_SEPARATOR = re.compile(r"([A-Za-z0-9]+)[^A-Za-z0-9]*$")
_WORD_AFTER_SEPARATOR = re.compile(r"^[^A-Za-z0-9]*([A-Za-z0-9]+)")
# A version is a digit run with nothing name-like in front of it. The 5 of F5, the 2 of ACF2, the
# 10 of OS10 and the 1 of WS1 are parts of product names, not versions; a lone leading `v` is the
# one letter that marks a version rather than a name (`v9`, `V9-x`, `v10.x`).
#
# The lookbehind rejects a digit as well as a letter, or the pattern would match the `0` of `OS10`
# after rejecting its `1`, and the `60` of `MaaS360` after rejecting its `3`.
_VERSION_RUN_RE = re.compile(r"(?<![a-z0-9])v?(\d+(?:[.-]\d+)*)")
# The caller's text gets the lenient pattern, and the asymmetry is deliberate. A run is read off a
# TITLE to decide whether to speak, so a non-version run there suppresses a note that was true. The
# same run is read off a QUERY only to decide whether to stay quiet (`qm & covered`), so an extra
# one costs nothing and a missing one is expensive: `covered` can hold junk digits this pattern's
# laxity is what lets a caller's own acronym supply back (rejecting the 5 of F5 here would also
# reject the 2 of a caller-typed L2S). `_classify` keeps a phrase-head digit such as "Layer 2" out
# of `covered`, but not a junk digit it has no rule for: `VMW_NSX-T_T-0_*`'s `product_keywords`
# folds `T-0` to tokens `t`, `0`, and the lone letter `t` is not a phrase head worth adding (see
# `_PHRASE_HEADS`'s curation standard), so `covered` holds that `0`. It stays silent rather than
# wrong only because a query specific enough to rank that benchmark alone must also name its `0`,
# which is a property of that benchmark pair rather than of this pattern.
_QUERY_RUN_RE = re.compile(r"\d+(?:[.-]\d+)*")


def build_idf(doc_token_sets):
    """Return (idf, df, n): smoothed inverse-document-frequency, raw doc-frequency, corpus size."""
    n = len(doc_token_sets)
    df = {}
    for tokens in doc_token_sets:
        for token in tokens:
            df[token] = df.get(token, 0) + 1
    idf = {token: math.log((n + 1) / (count + 1)) + 1 for token, count in df.items()}
    return idf, df, n


def _satisfied(token, doc_tokens):
    """Whether a document accounts for one query token: it holds the token, or the token is
    a synonym key whose full expansion it holds. States what _SYNONYMS has always asserted,
    at the point of comparison instead of by rewriting the text."""
    if token in doc_tokens:
        return True
    expansion = expansion_of(token)
    return expansion is not None and expansion <= doc_tokens


def _matched_tokens(query_tokens, doc_tokens):
    """Tokens of the query the doc accounts for. Single seam for per-token match relations;
    exact membership plus the synonym-expansion satisfaction above."""
    return {t for t in query_tokens if _satisfied(t, doc_tokens)}


def _coverage(query_tokens, doc_tokens, idf, matcher=_matched_tokens):
    """IDF-weighted share of the query's tokens the doc carries. `matcher` is a seam for the
    version-only path, which needs the padding-tolerant relation; product tokens never carry
    padding, so the default satisfaction relation (membership, or a synonym key's expansion) is
    right for them."""
    if not query_tokens:
        return 0.0
    numerator = sum(idf.get(t, 1.0) for t in matcher(query_tokens, doc_tokens))
    denominator = sum(idf.get(t, 1.0) for t in query_tokens)
    return numerator / denominator if denominator else 0.0


def _version_matched(query_versions, doc_versions):
    """The query's version tokens the doc satisfies, treating a zero-padded caller token as the
    version it pads.

    **Asymmetric on purpose: unpad what the CALLER wrote, never what DISA wrote.** Padding is a
    caller-side spelling artifact, and `08` for 8 is how an inventory tool writes it. Canonicalizing
    the doc side as well would make `4` and `04` one version, and Canonical writes 22.04, so a
    caller who said 'Ubuntu 4' would score 100 against Ubuntu 22.04 and be auto-scoped to it
    confidently. That is a wrong answer in the selection path rather than a wrong sentence, so the
    relation stays one-way.

    Known and accepted: if DISA ever writes a zero-padded MAJOR, a caller naming it bare would be
    told the knowledge base does not hold it. No such title exists (`04`, Ubuntu's minor, is the
    only padded version token in current titles), and separating the two cases needs the major and minor
    structure that `normalize`'s flat token set has already discarded.
    """
    return {
        version for version in query_versions if version in doc_versions or _unpadded_version(version) in doc_versions
    }


def _as_corpus_versions(query_versions, idf):
    """The caller's version tokens in the spelling the corpus uses, for the IDF-weighted path.

    A padded token appears in no benchmark, so `idf.get` falls to its 1.0 default on BOTH sides of
    _coverage's ratio: the match this feature exists to create is weighted at the floor, and an
    unmatched padded token is charged 1.0 where the bare spelling is charged its real rarity
    (idf['1'] is 4.88). Without the rewrite, '01.0' would rank IIS 10.0 above the Tier 1
    benchmarks that '1.0' puts first.

    Rewriting the whole set, matched or not, is what makes the two spellings score identically
    everywhere. Ubuntu's `04` is left alone because the corpus really does hold it.
    """
    return {version if version in idf else _unpadded_version(version) for version in query_versions}


def score(qp, qv, dp, dv, idf):
    """Product-dominant IDF-coverage score in 0..100. Product identity outweighs version so a
    benchmark sharing no product token cannot rank high on a year match alone."""
    if not qp:
        # A version-only query ('2019', '08') still ranks. It needs both halves: the corpus's own
        # spelling so the IDF weights are real (see _as_corpus_versions), and the padding-tolerant
        # relation so a token the corpus does happen to hold in padded form, Ubuntu's 04, still
        # reaches a benchmark that writes it 4.
        return 100.0 * _coverage(_as_corpus_versions(qv, idf), dp | dv, idf, _version_matched)
    # A query that names a product means it. Without this a doc sharing only the VERSION would
    # score 0.8*0 + 0.2*1 = 20.0, which clears _SCORE_FLOOR: 'Netscape 10' would return
    # IIS_10-0_Server, IIS_10-0_Site, MariaDB_Enterprise_10-x and RHEL_10, none of them anything
    # like Netscape. The `not qp` branch above is the deliberate exception and is unaffected.
    if not _matched_tokens(qp, dp):
        return 0.0
    product = _coverage(qp, dp, idf)
    version = (len(_version_matched(qv, dv)) / len(qv)) if qv else 1.0
    return 100.0 * (_WEIGHT_PRODUCT * product + _WEIGHT_VERSION * version)


def is_high_confidence(qp, qv, dp, dv, df, n):  # noqa: PLR0913
    """High-confidence iff the query has at least one distinctive (rare) product token
    AND the benchmark contains every distinctive product token plus every version token.
    A query with no distinctive product token (e.g. bare "2022", or only generic words)
    is never high-confidence: it is presented as candidates, not auto-scoped."""
    distinctive_products = {t for t in qp if df.get(t, 0) <= _DISTINCTIVE_DF_RATIO * n}
    if not distinctive_products:
        return False
    # Version tokens go through _version_matched rather than a subset test, so a zero-padded
    # caller is auto-scoped where a bare one is. Product tokens go through _satisfied, so a
    # distinctive acronym held only via its spelled-out expansion still counts as present.
    doc_tokens = dp | dv
    return all(_satisfied(t, doc_tokens) for t in distinctive_products) and _version_matched(qv, doc_tokens) == qv


def _sorted_versions(versions):
    """Versions in reading order. A plain lexical sort renders RHEL as '10, 8, 9' and
    vSphere as '10.0, 7.0', so a dotted version sorts componentwise by value and
    anything else trails the numbers."""

    def by_value(component):
        # (width, digits) rather than int(component): for digit strings of equal width a lexical
        # compare IS a numeric compare, so this orders by value without int()'s
        # int_max_str_digits ceiling, which a caller can reach with 4,301 digits of query text.
        digits = component.lstrip("0")
        return (len(digits), digits)

    def key(version):
        # The raw string trails the numeric key rather than an empty one, so `4` and `04` order
        # deterministically. They compare equal numerically, and set iteration order is seeded, so
        # without it the same call can print `4, 04` or `04, 4` between runs.
        components = version.split(".")
        if all(component.isascii() and component.isdigit() for component in components):
            return (0, tuple(by_value(component) for component in components), version)
        return (1, (), version)

    return sorted(versions, key=key)


def _unpadded_version(version):
    r"""One version, one key: `08` and `8` are the same release written two ways.

    Compared as raw strings they are not, and the classifier would deny a version the same note
    lists as covered one sentence later: 'Oracle Linux 08' against `Oracle_Linux_8_STIG`, "covering
    8, 9".

    Stripped rather than round-tripped through int(): `str(int(version))` raises ValueError above
    CPython's int_max_str_digits, so a caller sending 4,301 digits would crash the call, on the
    silence path rather than the verdict path.

    isascii() guards the compare, not the crash. `qm` is built from `\d`, which matches every
    Unicode decimal, so an Arabic-Indic digit reaches here; leaving it unkeyed means it matches
    nothing and the classifier errs toward speaking rather than silently equating scripts.
    """
    if version.isascii() and version.isdigit():
        return version.lstrip("0") or "0"
    return version


def _version_runs(text):
    """Every version the text names, as written: `10-0` and `10.0` both give `10.0`.

    Read by the notes, so a benchmark pinned to one dotted version is not described as
    covering several. `normalize` tokenizes on `[a-z0-9]+`, so from tokens alone the IIS 10.0
    benchmark covers '0, 10' and JBoss 6.3 covers '3, 6', which reverses the reading order as
    well as splitting it.

    A digit belonging to a product's NAME is not a version, which is what _VERSION_RUN_RE's
    lookbehind decides. Without it the classifier would read the 5 of F5 and the 2 of ACF2 as
    versions, conclude those benchmarks are version-pinned, and withhold the version-agnostic note
    from them.

    A run immediately after a role-phrase head (`Layer 2`, `Tier 1`) is dropped the same way,
    for the same reason `_classify` drops it: the digit names the phrase, not a release.
    """
    lowered = text.lower()
    runs = set()
    for run in _VERSION_RUN_RE.finditer(lowered):
        head = re.search(r"([a-z0-9]+)\s+$", lowered[: run.start()])
        if head and head.group(1) in _PHRASE_HEADS:
            continue
        runs.add(run.group(1).replace("-", "."))
    return runs


def _version_majors(text):
    """The major of every version the CALLER's text names: `11.4` gives `11`, `22.04.3` gives `22`.

    Coverage is judged on the major alone, so naming a patch level of a major the knowledge
    base holds is not read as naming a version it lacks. Without this, nearly every versioned
    benchmark would produce a false 'not covered' for a caller who names a patch level, some
    while the same call confidently auto-scopes to the very benchmark the note denies.

    Reads runs with _QUERY_RUN_RE rather than _version_runs, for the reason given there: this set
    only ever buys silence, so it must not be narrowed.
    """
    return {run.group(0).replace("-", ".").split(".")[0] for run in _QUERY_RUN_RE.finditer(text.lower())}


def _covered_versions(tier_written, covered):
    """The versions a tier holds, as their titles write them, for a note to show a caller.

    Keeps only the runs `normalize` also read as a version, because the run regex sees raw title
    text and so extracts 86 from x86, 2 from L2S, 2 from DB2 and 2740 from SEL-2740S; note A
    would otherwise name them as versions this knowledge base covers.

    A run survives on ANY shared component rather than all of them, because `normalize` can glue
    part of a real version to a letter: `IBM DB2 V10.5 LUW` yields the versions {5} while its
    title writes 10.5, and demanding every component would empty the filter and fall back to
    "covering 5", a version that does not exist. Junk runs are unaffected either way, since they
    share no component at all. The fallback stays for a tier whose written form and whose tokens
    disagree on every run.
    """
    written = {run for run in tier_written if any(part in covered for part in run.split("."))}
    return _sorted_versions(written or covered)


def _version_coverage(hits, qp, qv, qm, index, df, n):  # noqa: PLR0913
    """Whether the query names a product version this knowledge base does not hold.

    Query-level, not per-hit: the caller stamps one verdict onto every row. Returns None
    for every ambiguous case, because a false "not covered" is far more expensive than a
    silence. The distinctive-token test is is_high_confidence's held-test with the version
    term dropped: both go through _satisfied, so a distinctive acronym held only via its
    expansion (an `mdb` query against a document that spells out `mongodb`) counts as
    present here too, exactly as it does for confidence. Without the held-test at all,
    'windows 10 desktop' would report the Intune MDM benchmark, whose title carries
    'desktop' but not 'windows', as a version-agnostic Windows STIG.

    `qv` is every version token the query named and decides whether a version was named at
    all; `qm` is just the majors, from _version_majors, and decides coverage. `index` maps
    stig_id to its `tokens`, its version `versions` and every version its title `written`.
    All three are needed and none substitutes for another: tokens identify the product,
    versions decide coverage, and the written form both renders the answer and proves a
    benchmark is version-pinned when `normalize` could not see that it was.

    `query_versions` in the returned dict is diagnostic only. No note reads it, because the
    decomposed form ('0, 120, 6099' for 120.0.6099) reorders the caller's own words.
    """
    if not hits or not qv:
        return None
    distinctive = {token for token in qp if df.get(token, 0) <= _DISTINCTIVE_DF_RATIO * n}
    if not distinctive:
        return None
    top = max(hit["score"] for hit in hits)
    tier = sorted({hit["stig_id"] for hit in hits if hit["score"] == top})
    # index is built from the same docs the hits come from, so a missing stig_id is a caller
    # error worth raising on rather than a case to default away.
    if not all(_satisfied(t, index[stig_id]["tokens"]) for stig_id in tier for t in distinctive):
        return None
    tier_versions = [index[stig_id]["versions"] for stig_id in tier]
    tier_written = {written for stig_id in tier for written in index[stig_id]["written"]}
    covered = {version for versions in tier_versions for version in versions}
    if _version_matched(qm, covered):
        # Silent as soon as the tier holds ANY major the query named, judged against the
        # tier's UNION rather than member by member.
        #
        # The union, because reporting "not covered" while listing those same versions as
        # covered is a contradiction: 'vmware vsphere 7 0 vcenter appliance photon os 4 0'
        # asks for {0, 4, 7} against a tier covering {0, 4, 7, 8}. The union also subsumes the
        # single-benchmark case.
        #
        # Any rather than all, because a query yields majors the tier cannot be expected to
        # hold: 'Windows Server 2019 R2' gives {2019, 2} against a tier covering {2019}, and
        # demanding all of them would deny the benchmark the query just found.
        #
        # Through _version_matched, so a zero-padded caller token matches the version it pads. One
        # way only: see that function for why unpadding DISA's side is unsafe.
        return None
    if all(tier_versions):
        verdict = "uncovered"
    elif not any(tier_versions) and not tier_written:
        # A title naming a number is version-pinned even when `normalize` cannot see it, so a
        # written run with no version token means the two disagree and neither can be trusted.
        # Calling such a tier "not version-specific" is a false statement about the knowledge
        # base AND an invitation to apply Oracle 19c remediation to a 12c database.
        #
        # The classifier's index reads glued versions (see `glued_versions`, which `normalize`
        # deliberately does NOT call), so what still reaches here is mostly model names:
        # `HPE 3PAR SSMC` and `SEL-2740S` arrive because _VERSION_RUN_RE reads a run out of a
        # MODEL NAME, 3 and 2740, that no token confirms. Silence either way, because the tell
        # is only that the two readings disagree, not which one is right.
        #
        # The tell is that the verdict would otherwise carry a non-empty covered_versions
        # while claiming nothing is versioned, which contradicts itself.
        verdict = "version-agnostic"
    else:
        return None
    return {
        "verdict": verdict,
        "benchmarks": tier,
        "covered_versions": _covered_versions(tier_written, covered),
        "query_versions": _sorted_versions({_unpadded_version(v) for v in qv}),
    }


def _file_identity(path):
    """What makes one version of a file different from another, cheaply."""
    stat = os.stat(path)
    return (str(path), stat.st_mtime_ns, stat.st_size)


def _load_aliases():
    """The alias table, cached on the file as it is at call time.

    Keyed on `_ALIASES_PATH` read HERE rather than captured at import, because tests monkeypatch it
    to disable alias matching, and one of them exists precisely because an alias hit scores 100.0
    unconditionally and would otherwise make its assertions vacuous. A cache that missed the swap
    would hand it the real aliases and it would pass for the wrong reason.

    Frozen for the same reason `_build_corpus`'s result is: it outlives the call, and an alias hit is
    scored 100.0 and confident outright, so a mutated pattern list does not degrade an answer, it
    fabricates one. The values are tuples as well as the mapping being a proxy, since a proxy over a
    dict of lists still hands out mutable lists.
    """
    key = _file_identity(_ALIASES_PATH)
    cached = _ALIASES_CACHE.get(key)
    if cached is None:
        if len(_ALIASES_CACHE) >= _ALIASES_CACHE_MAX:
            _ALIASES_CACHE.clear()
        loaded = yaml.safe_load(_ALIASES_PATH.read_text()) or {}
        cached = _ALIASES_CACHE[key] = MappingProxyType(
            {stig_id: _alias_patterns(stig_id, patterns) for stig_id, patterns in loaded.items()}
        )
    return cached


def _alias_patterns(stig_id, patterns):
    """One entry's patterns as a tuple, raising on the two YAML shapes that read as a list and are not.

    A bare `RHEL_9_STIG:` parses to None and a scalar `RHEL_9_STIG: "rhel 9"` parses to a string, whose
    characters then iterate as one-letter patterns. Both would otherwise be silent, the scalar in the
    worse way: `_alias_ids` normalizes 'r', 'h', 'e' and matches whatever query contains them.
    """
    if not isinstance(patterns, (list, tuple)):
        raise ValueError(
            f"alias entry '{stig_id}' in {_ALIASES_PATH} is {patterns!r}, not a list of phrases. "
            f"Write it as a YAML list, one quoted phrase per line, even for a single alias."
        )
    return tuple(patterns)


def _build_corpus(conn):
    """Everything `resolve` needs that depends on the corpus rather than the query: most of an
    uncached call, and the reason this is cached at all.

    **Everything returned is immutable, and that is the point rather than tidiness.** This lives for
    the life of the connection and is handed to every later `resolve`, so one in-place write anywhere
    downstream would silently change every subsequent answer on that connection, for as long as the
    process runs. Frozen rather than copied per call because a copy of every row and its token sets
    is most of the work the cache exists to avoid; the token sets arrive already frozen from
    normalize's Tokens construction, and wrapping `stigs` and `index_by_id` in MappingProxyType here
    costs one more pass and turns the silent corruption into an immediate TypeError at the line
    that does it.
    """
    stigs = tuple(MappingProxyType(stig) for stig in stigs_for_resolver(conn))
    docs = tuple((stig, normalize(f"{stig['title']} {stig['product_keywords']}")) for stig in stigs)
    idf, df, n = build_idf([t.product | t.version for _, t in docs])
    # `versions` is widened with the versions glued to a letter, and `docs` above is NOT. That
    # asymmetry is the whole design: the classifier needs to know a benchmark covers 19c, while a
    # version token in `docs` would reach build_idf, score and is_high_confidence, where it would
    # answer `Windows 11` with a Postgres STIG (see `glued_versions`). `tokens` stays as the
    # documents have it, since it only ever answers "does this benchmark carry the product the
    # caller named".
    #
    # Written versions come from the title alone: product_keywords repeats the title with
    # every dotted version also split apart, so 'iis 10 0' there would undo _version_runs.
    index_by_id = MappingProxyType(
        {
            stig["stig_id"]: MappingProxyType(
                {
                    "tokens": t.product | t.version,
                    "versions": t.version | glued_versions(t.product),
                    "written": frozenset(_version_runs(stig["title"])),
                    "expanded": t.expanded,
                }
            )
            for stig, t in docs
        }
    )
    # Derived here rather than in _split because it is a property of the corpus, not of the
    # caller's text, and this is where corpus-derived facts are computed once per connection.
    straddling = _straddling_pairs(stigs)
    return stigs, docs, MappingProxyType(idf), MappingProxyType(df), n, index_by_id, straddling


def _corpus(conn):
    """The corpus this connection reads, derived once and kept ON the connection.

    Not keyed on the KB file; see CorpusCachingConnection for why.

    A connection that cannot carry the attribute is answered without caching rather than refused: a
    bare `sqlite3.Connection` has no `__dict__`, and a caller may reasonably pass one.
    """
    cached = getattr(conn, _CORPUS_ATTR, None)
    if cached is None:
        cached = _build_corpus(conn)
        try:
            setattr(conn, _CORPUS_ATTR, cached)
        except AttributeError:
            pass
    return cached


def _straddling_pairs(stigs):
    """The (word before, word after) pairs that bracket a separator inside a benchmark's OWN
    title, so `_split` can tell a separator in a product name from one between two products.

    DISA ships four such titles, three of them the z/OS SDSF family. Split, those three become
    indistinguishable: the fragment holding 'System Display' names none of ACF2, RACF or TSS,
    ties all three at 100.0, and every one of them comes back high confidence, so a caller who
    named one product is auto-scoped to three.

    **Read off the bracketing words, not matched against the title.** A substring test needs
    DISA's exact spelling, `z/OS ... (SDSF) ...`, and a caller writes it without the slash and
    without the parenthetical, so the protection never fires on the shape that actually
    arrives, leaving the canonical case unprotected.

    This is DATA, not a curated list: a future DISA title carrying a separator adds a pair with
    no code change. That is intended, since the pair is by construction part of a real product
    name, but it means a library refresh can change splitting silently, which is why
    tools/corpus_conformance.py reports the set size.

    A pair records the two bracketing words and nothing about which separator bracketed them, so
    it protects both spellings of the description's separator against a title that only ever
    justified one: no current title contains a comma, yet `('display', 'search')` also protects
    `display, search`, a spelling no title writes.
    """
    pairs = set()
    for stig in stigs:
        title = stig["title"]
        for separator in _SPLIT_RE.finditer(title):
            before = _WORD_BEFORE_SEPARATOR.search(title[: separator.start()])
            after = _WORD_AFTER_SEPARATOR.search(title[separator.end() :])
            if before and after:
                pairs.add((before.group(1).lower(), after.group(1).lower()))
    return frozenset(pairs)


def _split(description, protected=frozenset()):
    """Divide a description at separators, except where the separator sits inside a benchmark's
    own product name. `protected` comes from _straddling_pairs; the default reproduces the
    unprotected behavior exactly, so this function is testable without a knowledge base.

    The protection applies to the SEPARATOR and not to the phrase. Protecting the phrase merges
    'Application Security and Development and RHEL 9' into one fragment and loses the second
    product; pinned by
    test_split__a_protected_name_beside_a_second_product__still_divides_at_the_other_separator.
    """
    pieces, last = [], 0
    for separator in _SPLIT_RE.finditer(description):
        before = _WORD_BEFORE_SEPARATOR.search(description[: separator.start()])
        after = _WORD_AFTER_SEPARATOR.search(description[separator.end() :])
        if before and after and (before.group(1).lower(), after.group(1).lower()) in protected:
            continue
        pieces.append(description[last : separator.start()])
        last = separator.end()
    pieces.append(description[last:])
    return [piece.strip() for piece in pieces if piece.strip()]


def _alias_ids(qp, qv, stigs, aliases):
    """stig_ids whose alias patterns are a normalized-token subset of the query fragment.

    The query's version tokens are joined by their unpadded forms, in the same direction as
    _version_matched: an alias pattern is written here, so a caller who spells the version `010`
    must still reach the pattern that says `10`, so `iis site 010` and `iis site 10` agree.

    The DIRECTION is shared; the safety is not. `is_high_confidence` pairs the relation with a test
    that every caller version token is satisfied, while an alias match only needs the pattern to be
    a subset of the query, so a version token the pattern does not mention is ignored and an alias
    hit is scored 100.0 and confident outright. A padded minor therefore reaches a sibling major's
    alias exactly as a bare minor does: `RHEL 8.09` and `RHEL 8.9` both scope RHEL 8 and RHEL 9.
    That breadth belongs to aliases, not to this relation.

    A pattern token that is a synonym key is exempt from the subset test: its expansion tokens are
    already in the requirement. Without this, retention (which keeps the key in the pattern's
    literal set) would demand the query contain the acronym itself, and `rhel 9` would stop
    matching a spelled-out caller.
    """
    query = qp | qv | {_unpadded_version(version) for version in qv}
    matched = set()
    for stig in stigs:
        for pattern in aliases.get(stig["stig_id"], []):
            p = normalize(pattern)
            required = (p.product | p.version) - {t for t in p.product if expansion_of(t) is not None}
            if required and required <= query:
                matched.add((stig["stig_id"], pattern))
                break
    return matched


def _annotate(stig_id, version, build, entries):
    """(applicable, reason, wanted_version) for one benchmark row at one build. Rows are
    annotated rather than dropped so a caller can see the majors that exist and why one
    does not apply. wanted_version is the major that actually applies to the build; it is
    only meaningful (non-None) when reason is "superseded-major", and lets a renderer say
    which major the caller's build needs when this row is the only one left to say it."""
    if applicability.governing_entry(stig_id, entries) is None:
        return True, ("ungoverned-build" if build is not None else None), None
    if build is None:
        return True, "ambiguous-no-build", None
    wanted = applicability.applicable_version(stig_id, build, entries)
    if wanted is None:
        return False, "no-official-stig", None
    if wanted == version:
        return True, "scoped", None
    return False, "superseded-major", wanted


def _origin_rank(hit):
    # Library content outranks anything else only when scores tie. Selection guarantees
    # one origin per (stig_id, major), so this only ever fires across different
    # benchmarks, which is exactly where preferring current guidance is right.
    #
    # 0 means library because this feeds an ascending sort (see rank() inside
    # _limit_by_benchmark). orchestrator._origin_rank shares this name and returns the
    # opposite, 1 for library, because it feeds a max-style comparison. Both are correct
    # in place; copying either one over the other silently inverts the rule.
    return 0 if hit["origin"] == "library" else 1


def _tied_with_last_kept(rows, ranked, limit):
    """How many benchmarks the cap dropped despite scoring as well as the last one it kept.

    Benchmarks dropped from a strictly lower tier are not counted: they were ranked out on
    merit, and a note about them would report a correct decision as a loss. Compared with
    _SCORE_TIE_EPSILON for the same reason resolve()'s high-confidence clear is: these are
    summed floats and two benchmarks that tie mathematically can differ in the last bit.
    """
    if len(ranked) <= limit:
        return 0
    best_score = {}
    for hit in rows:
        best_score.setdefault(hit["stig_id"], hit["score"])
    cutoff = best_score[ranked[limit - 1]]
    return sum(1 for stig_id in ranked[limit:] if abs(best_score[stig_id] - cutoff) <= _SCORE_TIE_EPSILON)


def _limit_by_benchmark(hits, limit, unnamed):
    """Keep every row of the top `limit` benchmarks (stig_id), ranked by each benchmark's
    best-scoring row. All majors of a benchmark share the same title and keywords, so they
    score identically; grouping by benchmark before truncating is what stops the cut from
    landing between a benchmark's applicable and superseded rows.

    Among benchmarks that still tie on score, a HIGH-CONFIDENCE benchmark ranks first, then a
    library-origin one (_origin_rank), and then the one carrying the fewest DOCUMENT tokens its
    winning query fragment did not name (`unnamed`, keyed by stig_id; see resolve() for what
    "winning" means once a description splits into more than one fragment). "Document" is the
    title plus `product_keywords`, not the title alone, and `product_keywords` folds in the
    benchmark's own stig_id (see `_keywords` in the ingest orchestrator), so a token can be
    unnamed without appearing in the title at all: for 'Adobe Acrobat DC Continuous Track',
    specificity ranks `Adobe_Acrobat_Reader_DC_Continuous_Track_STIG` above
    `Adobe_Acrobat_Pro_DC_Continuous_STIG`, since both are origin `library` and Pro's document
    carries both the title's `professional` and the id-folded `pro`, while Reader's id adds
    nothing its title does not already have.

    Specificity is also what lets a query naming a parent product reach the parent instead of
    falling back to ASCII order of stig_id: 'vCenter 8.0' ties `VMW_vSphere_8-0_vCenter_STIG`
    with its nine appliance components at 100.0, and the parent carries fewer unnamed document
    tokens than any of them. Without this key the parent (sorting after all nine `VCSA_*`
    siblings, lowercase `v` being ASCII-greater than uppercase `V`) would rank tenth of ten.
    `stig_id` stays the last key, so the order is still total and reproducible when specificity
    ties too.

    Confidence ranks BEFORE origin and specificity because tools._resolve_scope filters
    `high_confidence` out of an ALREADY CAPPED list: a confident benchmark cut here is not
    merely ranked lower, it is absent from the scope and the caller is told nothing could be
    identified. For 'tier 4', `score` reads product coverage against `dp` alone while
    `is_high_confidence` satisfies against `dp | dv`, so NSX-T rows that hold no 4 at all tie
    with the NSX 4.x rows that hold it as a version; ranked by specificity first, the NSX-T rows
    would take four of the five slots and the scope would hold only ONE of the confident
    benchmarks. The same key makes `2 Switch` reach the benchmarks spelling "Layer 2" in words,
    which hold the query's `2` as a VERSION token, while the distinctive PRODUCT token gating
    confidence is `switch`; `_L2S_` benchmarks that spell the 2 only in their id miss it. That
    matches what `Layer 2 Switch` returns.

    Confidence sits after score for honesty rather than for effect. resolve() has already
    cleared `high_confidence` on every row more than `_SCORE_TIE_EPSILON` below the top score,
    and this is its only caller, so no confident row more than a tie's width below the top can
    reach the key. The protection against hoisting a confidently-wrong hit over a better-scoring
    one comes from that clear, not from this ordering.

    One sort, not two: the benchmark order is read back off the sorted rows, so row order and
    benchmark order cannot disagree.

    Returns the kept rows and the number of benchmarks dropped that scored as well as the
    last one kept, which is the only truncation a caller can do anything about.
    """

    def rank(hit):
        return (
            -hit["score"],
            not hit["high_confidence"],
            _origin_rank(hit),
            unnamed[hit["stig_id"]],
            hit["stig_id"],
        )

    rows = sorted(hits, key=lambda hit: (*rank(hit), hit["version"]))
    ranked = list(dict.fromkeys(hit["stig_id"] for hit in rows))
    top = set(ranked[:limit])
    return [hit for hit in rows if hit["stig_id"] in top], _tied_with_last_kept(rows, ranked, limit)


def _coverage_per_fragment(fragment_candidates, index, df, n):
    """One version-coverage verdict per fragment that has something to report.

    Computed over each fragment's OWN candidates, and before _limit_by_benchmark drops all but
    the top few benchmarks. Both halves are load bearing and neither is obvious.

    Per fragment, because `best` merges every fragment into one map and a tier read off that
    map belongs to whichever fragment scored highest. For 'RHEL 7 and Windows Server 2025' the
    merged tier holds the confident Windows benchmark, so the classifier would be asked about a
    tier that holds the version it was handed and stay silent about RHEL 7, which 'RHEL 7'
    alone explains.

    Before the cap, because the cap cuts score-tied benchmarks on a tiebreak that knows nothing
    about version coverage, so a tier read afterwards could have lost the version-less member
    that makes it mixed.

    A fragment whose candidate map is EMPTY is still passed through rather than skipped here:
    _version_coverage's own `if not hits` guard is the single place that decides to stay
    silent, and duplicating it at the call site would put one rule in two places.

    Each verdict adds THREE keys to what _version_coverage returns. `fragment` is the text it
    speaks for, which a note quotes instead of the whole description. `fragment_confident` says
    whether THIS fragment matched something confidently, and is the only one of the three the
    note gate reads; it is computed here because the `high_confidence` that reaches a row belongs
    to whichever fragment won that key in the merged map, and reading that answers a different
    question. `matched_benchmarks` is informational and nothing reads it: this fragment's own
    candidates that survive the cap, so a caller naming two products can tell which candidate
    answers which half.

    A fragment with nothing to report contributes nothing, so the result is [] and never None:
    every reader iterates rather than testing for a sentinel. Identical verdicts are collapsed,
    because a literally repeated fragment ('RHEL 7 and RHEL 7') otherwise renders the same
    sentence twice.
    """
    coverage = []
    for fragment, qp, qv, qm, own in fragment_candidates:
        verdict = _version_coverage(own.values(), qp, qv, qm, index, df, n)
        if verdict is None or any(seen["fragment"] == fragment for seen in coverage):
            continue
        # The fragment's OWN top score, not the query's. Compared with the same epsilon the
        # global clear uses, in the complementary direction (that one CLEARS when the gap
        # exceeds the epsilon), so for a single fragment, where this map and `best` hold the
        # same rows at the same scores, this is exactly the confidence a kept row ends up with.
        #
        # `default` cannot fire: an empty map makes _version_coverage return None on its own
        # `if not hits` guard and the continue above has already run. It is there so the line
        # states a total function rather than one whose safety depends on a caller two lines up.
        top = max((hit["score"] for hit in own.values()), default=0.0)
        coverage.append(
            {
                **verdict,
                "fragment": fragment,
                "fragment_confident": any(
                    hit["confident"] and top - hit["score"] <= _SCORE_TIE_EPSILON for hit in own.values()
                ),
                "matched_benchmarks": own,
            }
        )
    return coverage


def resolve(conn, description, limit=5):
    """Candidate STIG rows for a free-text description. `limit` caps the number of
    distinct benchmarks (stig_id) returned, not rows: a benchmark holding more than one
    STIG major contributes every major as its own row, so the result can hold more than
    `limit` rows.

    Every returned row carries `tied_omitted`: how many further benchmarks scored as well as
    the last one shown and were cut anyway. Zero when the cut fell on a score boundary.

    Every row also carries `version_coverage`, a LIST of verdicts, one per fragment of the
    description that has something to report, in the order the caller wrote them. Empty is []
    and never None. See _coverage_per_fragment for why a single merged reading cannot
    attribute a version to the fragment that named it.

    Each verdict adds three keys (`fragment`, `fragment_confident`, `matched_benchmarks`) to
    what _version_coverage returns; _coverage_per_fragment documents them.

    Before scoring, the description is divided into fragments at separators (`and`, commas),
    except where a separator sits inside a benchmark's own product name, per `_straddling_pairs`.
    Naming one member of a benchmark family whose own title carries such a separator (the real
    library's example is the z/OS SDSF trio: ACF2, RACF, TSS) scopes only that member and not its
    siblings; pinned on a synthetic fixture reproducing the shape by
    test_resolve__a_name_containing_a_separator__scopes_only_the_sibling_the_caller_named. The
    protection is keyed on the bracketing WORDS, not on which product is being described, so a
    description whose own wording happens to match a protected pair for an unrelated reason is
    also left undivided. The merged fragment then carries tokens from both the named product
    and the coincidentally-matched benchmark, which dilutes past the confidence gate for both,
    so the caller's scope can go EMPTY rather than merely miss a sibling. That loss is known and
    accepted rather than fixed, and it is pinned by
    test_resolve__ordinary_english_matching_a_protected_pair__pins_the_accepted_empty_scope_loss.
    """
    stigs, docs, idf, df, n, index_by_id, straddling = _corpus(conn)
    aliases = _load_aliases()
    entries = applicability.load_entries()
    fragments = _split(description, straddling) or [description]

    best = {}
    unnamed_by_key = {}
    # One entry per fragment, holding what _version_coverage needs to classify that fragment
    # ALONE; see _coverage_per_fragment for why `best` cannot serve. `stig_id` and `score` are
    # what _version_coverage reads; `confident` is recorded beside them because the flag that
    # ends up on a row cannot answer a question about one fragment.
    fragment_candidates = []
    for fragment in fragments:
        build, stripped_fragment = applicability.extract_build(fragment, entries)
        q = normalize(stripped_fragment)
        qp, qv = q.product, q.version
        own = {}
        fragment_candidates.append((fragment, qp, qv, _version_majors(stripped_fragment), own))
        alias_hits = dict(_alias_ids(qp, qv, stigs, aliases))
        for stig, d in docs:
            dp, dv = d.product, d.version
            if stig["stig_id"] in alias_hits:
                hit_score, matched_on, confident = 100.0, f"alias:{alias_hits[stig['stig_id']]}", True
            else:
                hit_score = score(qp, qv, dp, dv, idf)
                if hit_score < _SCORE_FLOOR:
                    continue
                matched_on, confident = "keyword", is_high_confidence(qp, qv, dp, dv, df, n)
            # Key by (stig_id, version): a benchmark pinned to a product release train
            # (e.g. vSphere V1 vs V2) has multiple versions that must both surface.
            key = (stig["stig_id"], stig["version"])
            # Assigned rather than compared: `stigs.PRIMARY KEY (stig_id, version)` means `docs`
            # holds one row per key, so within a single fragment each key is reached exactly
            # once. `best` needs the comparison below only because it accumulates across
            # fragments; this map never does.
            #
            # `confident` is recorded per fragment and is NOT the same thing as the
            # `high_confidence` that ends up on the row. That one belongs to whichever fragment
            # won the key in the merged map, so reading it to ask "did THIS fragment match
            # something confidently" answers a different question: in 'SQL Server 2019 and
            # Windows Server 2022' the SQL fragment is a candidate for the Windows benchmark on the
            # shared token `server` alone, and that benchmark is confident because of the OTHER
            # fragment, so the row's flag would silence the note about SQL Server 2019.
            own[key] = {"stig_id": stig["stig_id"], "score": hit_score, "confident": confident}
            current = best.get(key)
            if current is None or hit_score > current["score"]:
                applicable, reason, wanted_version = _annotate(stig["stig_id"], stig["version"], build, entries)
                best[key] = {
                    "stig_id": stig["stig_id"],
                    "title": stig["title"],
                    "version": stig["version"],
                    "release_label": stig["release_label"],
                    "release_info": stig["release_info"],
                    "origin": stig["origin"],
                    "source_artifact": stig["source_artifact"],
                    "source_member": stig["source_member"],
                    "xccdf_status": stig["xccdf_status"],
                    "xccdf_status_date": stig["xccdf_status_date"],
                    "score": hit_score,
                    "matched_on": matched_on,
                    "high_confidence": confident,
                    "applicable": applicable,
                    "applicability": reason,
                    "wanted_version": wanted_version,
                    "build": build,
                }
                # Written in the same branch as best[key] and keyed the same way, so this
                # always holds the count for the fragment that actually won that (stig_id,
                # version) key, overwritten rather than reduced here. A running min across
                # fragments would keep a losing fragment's lower count once a later fragment
                # outscores it for the same key, so reducing happens once, below, after every
                # fragment has had its turn.
                unnamed_by_key[key] = len((dp | dv) - (qp | qv))
    # Reduced to one count per benchmark, min across its majors, only now that every fragment
    # has been through the loop and each key holds its true winning fragment's count.
    # _limit_by_benchmark ranks each benchmark by its best row. Majors normally share a title
    # and keywords, so their documents score identically, every major picks the same winning
    # fragment, and min is a no-op. It stays because nothing enforces that: title comes from
    # each major's own XCCDF file, not from stig_id, so a DISA rename between majors would give
    # them different documents and different counts. The multi_major_specificity_kb fixture
    # pins the min by hand-inserting two majors whose product_keywords differ.
    unnamed_by_id = {}
    for (stig_id, _version), count in unnamed_by_key.items():
        unnamed_by_id[stig_id] = min(count, unnamed_by_id.get(stig_id, count))
    # Before _limit_by_benchmark; see _coverage_per_fragment for why.
    coverage = _coverage_per_fragment(fragment_candidates, index_by_id, df, n)
    # Confidence alone is not a claim about rank: without this clear, a benchmark confident on one
    # rare shared token but outranked by better answers would still be auto-scoped.
    # `IBM z OS ACF2 19c` would scope to Oracle_Database_19c_STIG from FIFTH place, because `19c` is
    # the query's only distinctive token and Oracle holds it.
    #
    # Cleared HERE rather than filtered in the caller, so `resolve_system`'s own high_confidence
    # flag agrees with what gets scoped. Filtering downstream would leave the API advertising
    # high_confidence=True on a candidate while the scope note says nothing confidently matched.
    #
    # Compared with a tolerance because these are summed floats: on Python 3.11, whose sum() is
    # naive rather than Neumaier, two benchmarks that tie mathematically can differ in the last bit
    # (99.99999999999997 against 100.0), and an exact == would drop one of a tied pair from the
    # scope.
    top_score = max((hit["score"] for hit in best.values()), default=0.0)
    for hit in best.values():
        if hit["high_confidence"] and top_score - hit["score"] > _SCORE_TIE_EPSILON:
            hit["high_confidence"] = False
    kept, tied_omitted = _limit_by_benchmark(best.values(), limit, unnamed_by_id)
    # Payload only: the note gate reads `fragment_confident`, not this. Per fragment so a
    # two-product caller can tell which candidate answers which part of the query; narrowed to
    # the kept rows because a fragment can match dozens of benchmarks while at most `limit` are
    # shown, and this ships on every row of the response. Pinned as a payload contract by
    # test_resolve__a_fragment_matching_more_than_the_limit__lists_only_the_kept_benchmarks and
    # test_resolve__a_fragments_verdict__names_only_the_benchmarks_that_fragment_matched.
    kept_ids = {hit["stig_id"] for hit in kept}
    for verdict in coverage:
        verdict["matched_benchmarks"] = sorted(
            {stig_id for stig_id, _version in verdict["matched_benchmarks"]} & kept_ids
        )
    # Both stamped here, on the kept rows only, rather than returned alongside them: resolve
    # returns a bare list, so a verdict a caller needs has to live on the row itself, and
    # tied_omitted is a query-level count read off hit zero the same way version_coverage is.
    for hit in kept:
        hit["version_coverage"] = coverage
        hit["tied_omitted"] = tied_omitted
    return kept
