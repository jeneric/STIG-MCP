import hashlib
import shutil
import sqlite3
from contextlib import closing

from stig_mcp.kb import freshness, install, releases
from stig_mcp.kb.db import SCHEMA_VERSION
from stig_mcp.kb.queries import source_versions
from tests.conftest import open_db_for_test
from tests.kb.fake_github import FakeGitHub


def _meta(kb_path):
    return source_versions(open_db_for_test(kb_path))


def _upstream(kb_meta, **newer):
    """The release.json upstream block of a release built from exactly what kb_meta records."""
    base = {name: (kb_meta.get(name) or {}).get("version") for name in ("attack", "ctid_attack_version", "catalog")}
    base["stig_library"] = (kb_meta.get("stig_library") or {}).get("artifact")
    return {**{k: v for k, v in base.items() if v}, **newer}


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_newer_upstream__release_has_a_newer_attack__names_attack():
    kb_meta = {"attack": {"version": "19.1"}, "ctid_attack_version": {"version": "16.1"}}
    assert freshness.newer_upstream(kb_meta, {"attack": "19.2", "ctid_attack_version": "16.1"}) == ["attack"]


def test_newer_upstream__library_months_in_word_form__compare_by_date_not_text():
    kb_meta = {"stig_library": {"artifact": "U_SRG-STIG_Library_July_2026.zip"}}
    newer = {"stig_library": "U_SRG-STIG_Library_January_2027.zip"}
    assert freshness.newer_upstream(kb_meta, newer) == ["stig_library"]
    assert freshness.newer_upstream(kb_meta, {"stig_library": "U_SRG-STIG_Library_April_2026.zip"}) == []


def test_newer_upstream__catalog_dotted_versions__compare_numerically():
    kb_meta = {"catalog": {"version": "5.2.0"}}
    assert freshness.newer_upstream(kb_meta, {"catalog": "5.10.0"}) == ["catalog"]


def test_newer_upstream__value_that_does_not_parse__is_not_counted():
    kb_meta = {"attack": {"version": "19.1"}}
    assert freshness.newer_upstream(kb_meta, {"attack": "latest"}) == []


def test_newer_upstream__dotted_catalog_value_with_a_non_digit_segment__is_not_counted():
    # "+3" is not all digits, but int() reads it as 3, so without the isdigit guard 5.+3.0
    # would rank above 5.2.0 and count as newer.
    kb_meta = {"catalog": {"version": "5.2.0"}}
    assert freshness.newer_upstream(kb_meta, {"catalog": "5.+3.0"}) == []


def test_newer_upstream__library_order_cannot_read_a_date__is_not_counted():
    # A sunset archive's name carries no month or year at all, so catalog.library_order
    # reads (0, 0) from it; that must not be compared as older than a real library date.
    kb_meta = {"stig_library": {"artifact": "U_SRG-STIG_Library_Sunset.zip"}}
    published = {"stig_library": "U_SRG-STIG_Library_July_2026.zip"}
    assert freshness.newer_upstream(kb_meta, published) == []


def test_newer_upstream__ctid_attack_version_newer_alone__is_not_confused_with_ctid():
    # kb_meta also carries a "ctid" source, a differently-shaped version string for a
    # similarly-named source; a lookup that used that key instead of "ctid_attack_version"
    # would find nothing in `published` and wrongly report no newer source.
    kb_meta = {
        "ctid_attack_version": {"version": "16.1"},
        "ctid": {"version": "attack-16.1/rev5@04/16/2025"},
    }
    assert freshness.newer_upstream(kb_meta, {"ctid_attack_version": "17.0"}) == ["ctid_attack_version"]


def test_report__installed_file_is_the_newest_release__action_none(tmp_path, kb_path):
    github = FakeGitHub()
    published = _upstream(_meta(kb_path))
    github.publish("kb-2026-10-04", kb_path.read_bytes(), upstream=published)
    target = tmp_path / "data" / "stig_kb.sqlite"
    install.install_release(target, opener=github)
    result = freshness.report(target, _sha(target), _meta(target), github)
    assert result["action"] == "none"
    assert result["action"] in freshness.ACTIONS
    assert result["installed"]["release"] == "kb-2026-10-04"
    assert result["newest"]["release"] == "kb-2026-10-04"
    assert result["newest"]["upstream"] == published


def test_report__an_older_release_is_installed__action_install(tmp_path, kb_path):
    github = FakeGitHub()
    older = tmp_path / "older.sqlite"
    shutil.copyfile(kb_path, older)
    with closing(sqlite3.connect(older)) as conn, conn:
        conn.execute("UPDATE ingest_meta SET ingested_at = 'older'")
    github.publish("kb-2026-10-04", older.read_bytes())
    github.publish("kb-2026-10-11", kb_path.read_bytes())
    target = tmp_path / "data" / "stig_kb.sqlite"
    install.install_release(target, release="kb-2026-10-04", opener=github)
    result = freshness.report(target, _sha(target), _meta(target), github)
    assert result["action"] == "install"
    assert result["action"] in freshness.ACTIONS
    assert "kb-2026-10-11" in result["reason"]


def test_report__installed_release_is_withdrawn__names_it_no_longer_published(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-11", kb_path.read_bytes())
    target = tmp_path / "data" / "stig_kb.sqlite"
    install.install_release(target, opener=github)
    # Withdraw kb-2026-10-11 from the listing; only a different-content kb-2026-10-04 remains.
    github.releases = [entry for entry in github.releases if entry["tag_name"] != "kb-2026-10-11"]
    github.publish("kb-2026-10-04", b"not this file")
    result = freshness.report(target, _sha(target), _meta(target), github)
    assert result["action"] == "none"
    assert result["action"] in freshness.ACTIONS
    assert "kb-2026-10-11" in result["reason"]
    assert "withdrawn" in result["reason"]
    assert "kb-2026-10-04" in result["reason"]


def test_report__installed_release_republished_with_different_bytes__stays_none(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    target = tmp_path / "data" / "stig_kb.sqlite"
    install.install_release(target, opener=github)
    # The same tag is republished with different content (a corrected release); its sha256 no
    # longer matches what is installed, but the tag is still the newest published one.
    github.publish("kb-2026-10-04", b"a corrected but still-published payload")
    result = freshness.report(target, _sha(target), _meta(target), github)
    assert result["action"] == "none"
    assert result["action"] in freshness.ACTIONS
    assert result["installed"]["release"] == "kb-2026-10-04"
    assert "is current" in result["reason"]


def test_report__only_a_higher_schema_release_exists__fetches_its_release_json_once(tmp_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-11", b"schema 8 bytes", schema="8", built_with="0.3.0")
    result = freshness.report(tmp_path / "absent.sqlite", None, {}, github)
    assert result["action"] == "upgrade_package"
    assert result["action"] in freshness.ACTIONS
    release_json_url = f"{releases.DOWNLOAD_PREFIX}kb-2026-10-11/release.json"
    assert github.requested.count(release_json_url) == 1


def test_report__local_build_mixed_newer_and_older_upstream__reason_names_both(tmp_path, kb_path):
    kb_meta = _meta(kb_path)
    github = FakeGitHub()
    published = _upstream(kb_meta, attack="99.0", stig_library="U_SRG-STIG_Library_January_2020.zip")
    github.publish("kb-2026-10-04", b"not this file", upstream=published)
    result = freshness.report(kb_path, _sha(kb_path), kb_meta, github)
    assert result["action"] == "install"
    assert result["action"] in freshness.ACTIONS
    assert "attack" in result["reason"]
    assert "stig_library" in result["reason"]


def test_report__no_usable_knowledge_base__action_install(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    result = freshness.report(tmp_path / "absent.sqlite", None, {}, github)
    assert result["action"] == "install"
    assert result["action"] in freshness.ACTIONS


def test_report__local_build_older_than_the_release_upstream__action_install(tmp_path, kb_path):
    kb_meta = _meta(kb_path)
    github = FakeGitHub()
    github.publish("kb-2026-10-04", b"not this file", upstream=_upstream(kb_meta, attack="99.0"))
    result = freshness.report(kb_path, _sha(kb_path), kb_meta, github)
    assert result["action"] == "install"
    assert result["action"] in freshness.ACTIONS
    assert "attack" in result["reason"]


def test_report__local_build_as_fresh_as_the_release__action_none(tmp_path, kb_path):
    kb_meta = _meta(kb_path)
    github = FakeGitHub()
    github.publish("kb-2026-10-04", b"not this file", upstream=_upstream(kb_meta))
    assert freshness.report(kb_path, _sha(kb_path), kb_meta, github)["action"] == "none"


def test_report__rebuilt_locally_after_an_install__is_judged_as_a_local_build(tmp_path, kb_path):
    kb_meta = _meta(kb_path)
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes(), upstream=_upstream(kb_meta, attack="99.0"))
    github.publish("kb-2026-10-11", kb_path.read_bytes(), upstream=_upstream(kb_meta, attack="99.0"))
    target = tmp_path / "data" / "stig_kb.sqlite"
    install.install_release(target, release="kb-2026-10-11", opener=github)
    with closing(sqlite3.connect(target)) as conn, conn:
        conn.execute("UPDATE ingest_meta SET ingested_at = 'rebuilt locally'")
    result = freshness.report(target, _sha(target), _meta(target), github)
    assert result["installed"]["release"] is None
    assert result["action"] == "install"
    assert result["action"] in freshness.ACTIONS
    assert "attack" in result["reason"]


def test_report__newer_release_needs_a_higher_schema__action_upgrade_package(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    github.publish("kb-2026-10-11", b"schema 8 bytes", schema="8", built_with="0.3.0")
    target = tmp_path / "data" / "stig_kb.sqlite"
    install.install_release(target, release="kb-2026-10-04", opener=github)
    result = freshness.report(target, _sha(target), _meta(target), github)
    assert result["action"] == "upgrade_package"
    assert result["action"] in freshness.ACTIONS
    assert result["newer_schema_available"]["upgrade_to"] == "stig-mcp 0.3.0 or later"


def test_report__no_release_at_all_and_nothing_installed__action_build_locally(tmp_path):
    result = freshness.report(tmp_path / "absent.sqlite", None, {}, FakeGitHub())
    assert result["action"] == "build_locally"
    assert result["action"] in freshness.ACTIONS
    assert result["newest"] is None
    assert "stig-mcp-fetch" in result["reason"]
    assert "stig-mcp-ingest" in result["reason"]
    assert result["reason"].startswith("No published knowledge-base release")


def test_report__no_release_at_all_but_a_usable_kb_installed__action_none(kb_path):
    result = freshness.report(kb_path, _sha(kb_path), _meta(kb_path), FakeGitHub())
    assert result["action"] == "none"
    assert result["action"] in freshness.ACTIONS
    assert result["newest"] is None
    assert result["reason"] == (
        f"No published knowledge-base release for schema {SCHEMA_VERSION} yet, so there is nothing to "
        f"install; the installed knowledge base stays in use. Compare its sources with stig-mcp-fetch --check."
    )


def test_report__no_release_at_all_and_the_installed_kb_is_outdated__build_locally_says_why(tmp_path):
    result = freshness.report(tmp_path / "stig_kb.sqlite", None, {}, FakeGitHub(), not_ready_reason="schema_outdated")
    assert result["action"] == "build_locally"
    assert result["action"] in freshness.ACTIONS
    assert result["reason"] == (
        "The installed knowledge base cannot be used (schema_outdated). "
        f"No published knowledge-base release for schema {SCHEMA_VERSION} yet. Build one locally with "
        "stig-mcp-fetch and then stig-mcp-ingest."
    )


def test_report__only_a_higher_schema_release_and_nothing_installed__action_upgrade_package(tmp_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-11", b"schema 8 bytes", schema="8", built_with="0.3.0")
    action = freshness.report(tmp_path / "absent.sqlite", None, {}, github)["action"]
    assert action == "upgrade_package"
    assert action in freshness.ACTIONS


def test_report__installed_file_cannot_be_used__says_so_with_the_reason(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    result = freshness.report(tmp_path / "stig_kb.sqlite", None, {}, github, not_ready_reason="schema_outdated")
    assert result["action"] == "install"
    assert result["action"] in freshness.ACTIONS
    assert result["reason"] == "The installed knowledge base cannot be used (schema_outdated)."


def test_report__no_knowledge_base_file__says_none_is_installed(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    result = freshness.report(tmp_path / "absent.sqlite", None, {}, github, not_ready_reason="no_knowledge_base")
    assert result["reason"] == "No usable knowledge base is installed."
