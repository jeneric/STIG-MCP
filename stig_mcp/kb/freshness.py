"""Whether a newer knowledge base is published than the one installed, for check_sources.

Contacts only this project's releases. A knowledge base installed from a release is compared by
release; one built locally matches no release hash, so it is compared by the upstream versions
it records in ingest_meta against the ones the release's release.json names."""

from stig_mcp.ingest import catalog, upstream
from stig_mcp.kb import install, releases
from stig_mcp.kb.db import SCHEMA_VERSION

# Every action report can return, in the order the user guide lists them.
ACTIONS = ("none", "install", "upgrade_package", "build_locally")


def _dotted(version):
    parts = version.split(".")
    if not all(part.isdigit() for part in parts):
        raise ValueError(version)
    return tuple(int(part) for part in parts)


def _library(name):
    order = catalog.library_order(name)
    if order == (0, 0):
        raise ValueError(name)
    return order


# (ingest_meta source_name, the field it records, how to order two values)
_COMPARED = {
    "attack": ("version", upstream.version_key),
    "ctid_attack_version": ("version", upstream.version_key),
    "catalog": ("version", _dotted),
    "stig_library": ("artifact", _library),
}


def _upstream_diff(kb_meta, published):
    """(newer, older): the sources where published outranks kb_meta, and the sources where
    kb_meta outranks published. A value either side cannot order is counted in neither list:
    an unparseable name must not trigger a replacement, or a downgrade warning, either."""
    newer, older = [], []
    for name, (field, order) in _COMPARED.items():
        built = (kb_meta.get(name) or {}).get(field)
        release_value = published.get(name)
        if not isinstance(release_value, str) or not built:
            continue
        try:
            release_rank, built_rank = order(release_value), order(built)
        except (ValueError, upstream.UpstreamError):
            continue
        if release_rank > built_rank:
            newer.append(name)
        elif release_rank < built_rank:
            older.append(name)
    return newer, older


def newer_upstream(kb_meta, published):
    """The sources whose release value is newer than the knowledge base's. A value either side
    cannot order is not counted: an unparseable name must not trigger a replacement."""
    return _upstream_diff(kb_meta, published)[0]


def _installed(kb_path, kb_sha256):
    record = install.read_record(kb_path) or {}
    release = record.get("release") if kb_sha256 is not None and record.get("sha256") == kb_sha256 else None
    return {"sha256": kb_sha256, "release": release}


def _local_build_action(kb_meta, meta, newest):
    newer, older = _upstream_diff(kb_meta, meta["upstream"])
    if not newer:
        return "none", f"This local build is at least as current as release {newest.tag}."
    reason = f"Release {newest.tag} was built from newer {', '.join(newer)} than this local build."
    if older:
        reason += f" Installing would replace the newer local {', '.join(older)}."
    return "install", reason


def _nothing_usable(not_ready_reason):
    """The reason to install when no usable knowledge base is installed: none at all, or a file
    this server cannot answer from, named by readiness's reason."""
    if not_ready_reason is None or not_ready_reason == "no_knowledge_base":
        return "No usable knowledge base is installed."
    return f"The installed knowledge base cannot be used ({not_ready_reason})."


def _no_release_action(choice, kb_sha256):
    if choice.newer_schema is not None:
        return "upgrade_package"
    return "build_locally" if kb_sha256 is None else "none"


def _no_release_reason(action, message, not_ready_reason):
    if action == "none":
        return (
            f"No published knowledge-base release for schema {SCHEMA_VERSION} yet, so there is nothing to "
            f"install; the installed knowledge base stays in use. Compare its sources with stig-mcp-fetch --check."
        )
    if action == "build_locally" and not_ready_reason not in (None, "no_knowledge_base"):
        return f"{_nothing_usable(not_ready_reason)} {message}"
    return message


def _action(installed, kb_meta, newest, meta, found):
    if installed["sha256"] == meta["sha256"]["sqlite"]:
        return "none", f"The installed knowledge base is the newest release, {newest.tag}."
    if installed["release"] is not None:
        # Tag strings compare correctly as text only because TAG_RE pins them to kb-YYYY-MM-DD.
        if installed["release"] < newest.tag:
            return "install", f"Release {newest.tag} is newer than the installed {installed['release']}."
        if not any(release.tag == installed["release"] for release in found):
            return "none", (
                f"The installed release {installed['release']} is not among the published releases "
                f"(it may have been withdrawn); the newest published is {newest.tag}."
            )
        return "none", f"The installed release {installed['release']} is current."
    return _local_build_action(kb_meta, meta, newest)


def report(kb_path, kb_sha256, kb_meta, opener=None, not_ready_reason=None):
    """not_ready_reason is readiness's reason when no usable knowledge base is installed."""
    found = releases.list_releases(opener)
    choice = releases.choose(found, SCHEMA_VERSION)
    result = {"installed": _installed(kb_path, kb_sha256), "newest": None}
    if choice.newer_schema is not None:
        result["newer_schema_available"] = install.newer_schema_payload(choice.newer_schema, opener)
    newest = choice.compatible
    if newest is None:
        result["action"] = _no_release_action(choice, kb_sha256)
        message = install.no_release_message(choice, opener=opener, newer=result.get("newer_schema_available"))
        result["reason"] = _no_release_reason(result["action"], message, not_ready_reason)
        return result
    meta = releases.metadata(newest, opener)
    result["newest"] = {"release": newest.tag, **meta}
    if kb_sha256 is None:
        action, reason = "install", _nothing_usable(not_ready_reason)
    else:
        action, reason = _action(result["installed"], kb_meta, newest, meta, found)
    if action == "none" and choice.newer_schema is not None:
        action = "upgrade_package"
        reason += f" A newer knowledge base needs {result['newer_schema_available']['upgrade_to']}."
    result["action"], result["reason"] = action, reason
    return result
