"""Which STIG major applies to which product build.

A leaf module: it imports nothing from stig_mcp, so the offline ingest and the runtime
resolver can both depend on it without depending on each other.
"""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

RULES_PATH = Path(__file__).parent / "applicability.yaml"

# The rule file is a repository artifact rather than a generated one, so its own identity is a
# sound key: nothing replaces it under a running process the way ingest replaces the knowledge
# base. Bounded because tests point both RULES_PATH and the `path` argument at temporary files.
_ENTRIES_CACHE_MAX = 4
_ENTRIES_CACHE = {}

# Distinct from None on purpose. None means "this benchmark is governed, and no STIG
# applies to that build". NOT_GOVERNED means "no rule covers this benchmark at all".
# The first yields zero findings with an explanation; the second yields everything
# unfiltered. Conflating them silently empties a caller's results.
NOT_GOVERNED = object()


@dataclass(frozen=True)
class Entry:
    name: str
    id_pattern: re.Pattern
    build_pattern: re.Pattern
    thresholds: tuple
    source: str
    verified_against: str


def _required(name, raw, key, path):
    if key not in raw:
        raise ValueError(
            f"applicability entry '{name}' is missing required key '{key}'. Every entry "
            f"needs id_pattern, build_pattern and thresholds. See the header of {path}."
        )
    value = raw[key]
    if not value:
        raise ValueError(
            f"applicability entry '{name}' has key '{key}' but it is empty ({value!r}). Every "
            f"entry needs a non-empty id_pattern, build_pattern and thresholds. See the header "
            f"of {path}."
        )
    return value


def _compile(name, key, pattern):
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(
            f"applicability entry '{name}' has an invalid {key}: {pattern!r} ({exc}). Fix the pattern in {RULES_PATH}."
        ) from exc


def _build_pattern(name, pattern):
    compiled = _compile(name, "build_pattern", pattern)
    if "n" not in compiled.groupindex:
        raise ValueError(
            f"applicability entry '{name}' has a build_pattern with no named group 'n': "
            f"{pattern!r}. The group captures the update number; a match where it does not "
            f"participate means update 0. Fix the pattern in {RULES_PATH}."
        )
    return compiled


def _threshold_min(name, threshold, path):
    if "min" not in threshold:
        raise ValueError(
            f"applicability entry '{name}' has a threshold missing required key 'min': "
            f"{threshold!r}. Add a numeric min to every threshold. See {path}."
        )
    try:
        return int(threshold["min"])
    except (TypeError, ValueError) as exc:
        # Interpolate the raw row, not threshold['min']: for a malformed (non-mapping)
        # threshold row, re-subscripting the expression that just raised would produce a
        # chained TypeError naming neither the entry nor the file.
        raise ValueError(
            f"applicability entry '{name}' has a threshold whose 'min' is not numeric: "
            f"{threshold!r}. Fix the entry in {path}."
        ) from exc


def _threshold_version(name, threshold, path):
    # `.get("version")` would make a typo'd key (e.g. "versoin") indistinguishable from a
    # deliberate `version: null`, silently denying STIG scoping to a build that should be
    # governed instead of raising. A present key must be checked for explicitly.
    if "version" not in threshold:
        raise ValueError(
            f"applicability entry '{name}' has a threshold missing required key 'version': "
            f"{threshold!r}. Use version: null if no STIG applies to those builds. See {path}."
        )
    version = threshold["version"]
    if version is not None and not isinstance(version, str):
        raise ValueError(
            f"applicability entry '{name}' has a threshold with version {version!r} "
            f"(type {type(version).__name__}, expected a quoted string or null). Quote it "
            f'(e.g. "{version}") or use null: an unquoted YAML integer compares unequal to '
            f"every STIG version, which this knowledge base always stores as text. Fix the "
            f"entry in {path}."
        )
    return version


def _thresholds(name, raw, path):
    pairs = tuple(
        sorted(
            ((_threshold_min(name, t, path), _threshold_version(name, t, path)) for t in raw),
            key=lambda pair: -pair[0],
        )
    )
    if pairs[-1][0] != 0:
        raise ValueError(
            f"applicability entry '{name}' has no threshold with min: 0, so a build below "
            f"{pairs[-1][0]} would match no threshold at all. Add one, using version: null "
            f"if no STIG applies to those builds. See {path}."
        )
    return pairs


def _file_identity(path):
    """What makes one version of a file different from another, cheaply."""
    stat = path.stat()
    return (str(path), stat.st_mtime_ns, stat.st_size)


def load_entries(path=None):
    """The parsed rule file, cached on the file as it is at call time.

    Raises on a malformed entry rather than skipping it: a silently ignored rule file looks
    exactly like correct unfiltered behavior. A failure is never cached, so a broken file
    raises on every call and not only the first.

    `RULES_PATH` is read HERE rather than captured at import, because tests monkeypatch it. The
    returned list is a fresh copy of the cached one: `Entry` is frozen, but a caller that sorted
    or appended to the list it was handed would otherwise rewrite every later call's answer.
    """
    path = Path(path) if path else RULES_PATH
    key = _file_identity(path)
    cached = _ENTRIES_CACHE.get(key)
    if cached is None:
        if len(_ENTRIES_CACHE) >= _ENTRIES_CACHE_MAX:
            _ENTRIES_CACHE.clear()
        cached = _ENTRIES_CACHE[key] = tuple(_parse_entries(path))
    return list(cached)


def _parse_entries(path):
    doc = yaml.safe_load(path.read_text()) or {}
    return [
        Entry(
            name=name,
            id_pattern=_compile(name, "id_pattern", _required(name, raw, "id_pattern", path)),
            build_pattern=_build_pattern(name, _required(name, raw, "build_pattern", path)),
            thresholds=_thresholds(name, _required(name, raw, "thresholds", path), path),
            source=raw.get("source", ""),
            verified_against=raw.get("verified_against", ""),
        )
        for name, raw in doc.items()
    ]


def extract_build(text, entries):
    """The build number a description names, and the text with that token removed.

    Stripping matters as much as extracting. A build token appears in no benchmark title,
    so leaving it in makes it a distinctive-but-unmatchable query token, which is what
    stops the resolver auto-scoping on a description that carries a build today."""
    for entry in entries:
        match = entry.build_pattern.search(text)
        if match is None:
            continue
        captured = match.groupdict().get("n")
        remainder = f"{text[: match.start()]} {text[match.end() :]}"
        return (int(captured) if captured else 0), " ".join(remainder.split())
    return None, text


def governing_entry(stig_id, entries):
    """The entry whose id_pattern covers this benchmark, or None."""
    for entry in entries:
        if entry.id_pattern.search(stig_id):
            return entry
    return None


def applicable_version(stig_id, build, entries):
    """The STIG major that applies, None when the product had no STIG at that build, or
    NOT_GOVERNED when no rule covers the benchmark or no build was supplied."""
    entry = governing_entry(stig_id, entries)
    if entry is None or build is None:
        return NOT_GOVERNED
    for minimum, version in entry.thresholds:
        if build >= minimum:
            return version
    raise ValueError(
        f"applicability entry '{entry.name}' matched no threshold for build {build}. "
        f"Every entry must include a threshold with min: 0."
    )


def _entry_report(entry, governed):
    """(warnings, unmapped_row_count) for one entry against the rows it governs."""
    mapped = {version for _, version in entry.thresholds if version is not None}
    present = {version for _, version in governed}
    warnings, unmapped = [], 0
    for version in sorted(present - mapped):
        unmapped += sum(1 for _, row_version in governed if row_version == version)
        warnings.append(
            f"Applicability entry '{entry.name}' governs benchmarks at major '{version}', which "
            f"no threshold maps, so those rows are never scoped by build. Re-read {entry.source} "
            f"(rule verified against {entry.verified_against})."
        )
    for version in sorted(mapped - present):
        warnings.append(
            f"Applicability entry '{entry.name}' maps builds to major '{version}', which this "
            f"knowledge base does not hold. Check whether the compilation still ships it."
        )
    return warnings, unmapped


def check_against_kb(stig_rows, entries):
    """(info, warnings, unmapped_row_count) for the rules against what the KB holds.

    Reports rather than raises. A stale rule degrades to unfiltered behavior, which is
    safe, so it must never stop a build."""
    info, warnings, unmapped = [], [], 0
    for entry in entries:
        governed = [(stig_id, version) for stig_id, version in stig_rows if entry.id_pattern.search(stig_id)]
        if not governed:
            warnings.append(
                f"Applicability entry '{entry.name}' governs no benchmark in this knowledge base; "
                f"its id_pattern no longer matches anything. Re-check {entry.source}."
            )
            continue
        entry_warnings, entry_unmapped = _entry_report(entry, governed)
        warnings += entry_warnings
        unmapped += entry_unmapped
        # The governed count is reported every run because it is the only thing that makes
        # a PARTIAL id_pattern match visible: eleven governed benchmarks is a perfectly
        # valid number with nothing to compare it against.
        info.append(
            f"Applicability: '{entry.name}' governs {len({s for s, _ in governed})} benchmark(s), "
            f"{len(governed)} row(s), majors {sorted({v for _, v in governed})}."
        )
    return info, warnings, unmapped
