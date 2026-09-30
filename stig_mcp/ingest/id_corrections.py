"""Corrected identities for documents DISA stamped with another benchmark's id.

A leaf module of the ingest: it reads a curated YAML map and imports nothing else from this
package. The map's authority is DISA's own Overview PDF, the same relationship
stig_mcp.applicability has with U_VMW_vSphere_8-0_Overview.pdf, and for the same reason: the
PDF states the split in prose and names neither the XCCDF files nor the Benchmark/@id, so it is
something a human reads once and records here, not something to parse at ingest time.
"""

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import yaml

CORRECTIONS_PATH = Path(__file__).parent / "id_corrections.yaml"

# The map is a repository artifact rather than a generated one, so its own identity is a sound
# cache key: nothing replaces it under a running process. Bounded because tests point the path
# argument at temporary files.
_CACHE_MAX = 4
_CACHE = {}

# A correction only ever applies to a colliding pair, so a single document is never enough.
_MIN_DOCUMENTS = 2


@dataclass(frozen=True)
class Correction:
    match: str
    stig_id: str
    title: str


@dataclass(frozen=True)
class Entry:
    published_id: str
    documents: tuple
    source: str
    verified_against: str


def _text(published_id, row, key, index, path):
    value = row.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"id_corrections entry '{published_id}' document #{index} has {key}={value!r}. "
            f"Every document needs a non-empty match, stig_id and title. Fix the entry in {path}."
        )
    return value


def _row(published_id, row, index, path):
    if not isinstance(row, dict):
        raise ValueError(
            f"id_corrections entry '{published_id}' document #{index} is {row!r}, not a mapping. "
            f"Each document is a mapping with match, stig_id and title. Fix the entry in {path}."
        )
    return row


def _unique(published_id, documents, key, path):
    values = [getattr(document, key) for document in documents]
    if len(set(values)) != len(values):
        raise ValueError(
            f"id_corrections entry '{published_id}' has two documents sharing a {key} "
            f"({values!r}). Two documents correcting to one {key} would re-create the very "
            f"collision this file exists to resolve. Fix the entry in {path}."
        )


def _document(published_id, row, index, path):
    # Validate the row once and pass the checked mapping to every _text call. Keyword
    # arguments evaluate left to right, so an inline _row(...) only inside `match=` would make
    # the other two fields' safety depend on their position rather than on the check itself.
    row = _row(published_id, row, index, path)
    return Correction(
        match=_text(published_id, row, "match", index, path),
        stig_id=_text(published_id, row, "stig_id", index, path),
        title=_text(published_id, row, "title", index, path),
    )


def _documents(published_id, raw, path):
    rows = raw.get("documents") if isinstance(raw, dict) else None
    if not isinstance(rows, list) or len(rows) < _MIN_DOCUMENTS:
        raise ValueError(
            f"id_corrections entry '{published_id}' needs a 'documents' list of at least two "
            f"entries, because a correction only ever applies to a colliding pair. Found "
            f"{rows!r} in {path}."
        )
    documents = tuple(_document(published_id, row, index, path) for index, row in enumerate(rows))
    _unique(published_id, documents, "match", path)
    _unique(published_id, documents, "stig_id", path)
    return documents


def _file_identity(path):
    """What makes one version of a file different from another, cheaply."""
    stat = path.stat()
    return (str(path), stat.st_mtime_ns, stat.st_size)


def load_corrections(path=None):
    """The parsed correction map, cached on the file as it is at call time.

    Raises on a malformed entry rather than skipping it: a silently ignored correction is
    indistinguishable from having no correction at all. A failure is never cached, so
    a broken file raises on every call and not only the first.

    The result is a read-only view rather than a copy, matching how the resolver freezes its own
    module-level caches: copying to protect a cache is most of the work the cache avoids."""
    path = Path(path) if path else CORRECTIONS_PATH
    key = _file_identity(path)
    cached = _CACHE.get(key)
    if cached is None:
        if len(_CACHE) >= _CACHE_MAX:
            _CACHE.clear()
        cached = _CACHE[key] = MappingProxyType(_parse(path))
    return cached


def _parse(path):
    doc = yaml.safe_load(path.read_text()) or {}
    return {
        published_id: Entry(
            published_id=published_id,
            documents=_documents(published_id, raw, path),
            source=raw.get("source", ""),
            verified_against=raw.get("verified_against", ""),
        )
        for published_id, raw in doc.items()
    }


def correction_for(published_id, source_document, corrections):
    """The corrected identity for one document, or None when the map cannot name it.

    Returns None for every "the map does not cover this" case, including an ambiguous entry
    whose fragments match the same document twice, because the caller then falls back to the
    uncorrected same-key contest. One curation mistake must not abort a whole knowledge base
    build; the caller warns instead."""
    entry = corrections.get(published_id)
    if entry is None or not source_document:
        return None
    matched = [document for document in entry.documents if document.match in source_document]
    if len(matched) != 1:
        return None
    return matched[0]
