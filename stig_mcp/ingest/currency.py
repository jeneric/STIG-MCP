"""Per-source currency: what upstream has, what was downloaded, and what the knowledge base was
built from. Used by stig-mcp-fetch --check and --refresh.

A separate module from upstream because it reads the fetch manifest and DISA diff, and fetch
itself imports upstream. Never raises: a source that cannot be checked reports why."""

from pathlib import Path

from stig_mcp.ingest import catalog, fetch, upstream


def _key_or_none(version):
    try:
        return upstream.version_key(version)
    except upstream.UpstreamError:
        return None


def _versioned(upstream_version, downloaded, built, with_built):
    have = _key_or_none(downloaded)
    if have is None or upstream.version_key(upstream_version) > have:
        action = "refresh"
    elif with_built and built != downloaded:
        action = "ingest"
    else:
        action = "none"
    entry = {"upstream": upstream_version, "downloaded": downloaded, "action": action}
    if with_built:
        entry["built"] = built
    return entry


def _catalog(sources_dir, record, built, with_built, opener):
    local = Path(sources_dir) / fetch._TARGET_FILENAMES["catalog"]
    # The listing is read first and unconditionally: a missing local file must still reach the
    # network, so an unreachable listing reports unknown instead of a refresh no one can act on.
    upstream_sha = upstream.catalog_state(opener)
    changed = not local.is_file() or upstream.git_blob_sha(local) != upstream_sha
    # A catalog on disk with no recorded version (an upgrade from a release that recorded none,
    # or a hand-placed file) matches upstream by sha, yet only a refresh records its version.
    # Reading it as current would leave the build compared against nothing.
    if changed or record.get("version") is None:
        action = "refresh"
    elif with_built and built != record.get("version"):
        action = "ingest"
    else:
        action = "none"
    entry = {"upstream_changed": changed, "downloaded": record.get("version"), "action": action}
    if with_built:
        entry["built"] = built
    return entry


def _disa(manifest, built_library, with_built, opener):
    entries = fetch.selection(catalog.parse_index(catalog.fetch_listing(opener=opener)))
    changes = fetch.diff(entries, manifest)
    entry = {**changes, "action": "refresh" if changes["new"] or changes["resized"] else "none"}
    if with_built:
        entry["built"] = built_library
    return entry


def _run_isolated(checks):
    report = {}
    for name, check in checks.items():
        try:
            report[name] = check()
        except Exception as exc:  # a report that raises cannot say which source failed
            report[name] = {"status": "unknown", "reason": f"{type(exc).__name__}: {exc}"}
    return report


def _built(kb_meta, key, field="version"):
    return ((kb_meta or {}).get(key) or {}).get(field) or None


def _public_checks(sources_dir, manifest, kb_meta, opener):
    public, with_built = manifest["public"], kb_meta is not None
    return {
        "attack": lambda: _versioned(
            upstream.attack_latest(opener).latest.version,
            (public.get("attack") or {}).get("version"),
            _built(kb_meta, "attack"),
            with_built,
        ),
        "ctid": lambda: _versioned(
            upstream.ctid_latest(opener).attack_version,
            (public.get("ctid") or {}).get("attack_version"),
            _built(kb_meta, "ctid_attack_version"),
            with_built,
        ),
        "catalog": lambda: _catalog(
            sources_dir, public.get("catalog") or {}, _built(kb_meta, "catalog"), with_built, opener
        ),
    }


def public_report(sources_dir, kb_meta=None, opener=None):
    return _run_isolated(_public_checks(sources_dir, fetch.read_manifest(sources_dir), kb_meta, opener))


def currency_report(sources_dir, kb_meta=None, opener=None):
    manifest = fetch.read_manifest(sources_dir)
    checks = _public_checks(sources_dir, manifest, kb_meta, opener)
    checks["disa"] = lambda: _disa(manifest, _built(kb_meta, "stig_library", "artifact"), kb_meta is not None, opener)
    return _run_isolated(checks)
