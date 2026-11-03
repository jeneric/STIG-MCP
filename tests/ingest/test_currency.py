import json
import urllib.error

from stig_mcp.ingest import currency, fetch, upstream
from tests.ingest.test_fetch import _CATALOG_POST, _disa_bodies, _fetched, _Opener, _public_bodies, _selected


def _served(**overrides):
    bodies = {**_public_bodies(), **_disa_bodies()}
    bodies.update(overrides)
    return _Opener(bodies)


def _fetched_everything(tmp_path):
    fetch.fetch_public(tmp_path, opener=_served())
    _fetched(tmp_path, *_selected())


def _manifest_without_public_records(tmp_path):
    """What a user upgrading from a release without public records has: every public file on
    disk from an earlier fetch, the catalog byte for byte what upstream serves, and a manifest
    whose DISA entries survive but which records no public source at all."""
    _fetched_everything(tmp_path)
    path = tmp_path / fetch.MANIFEST_NAME
    body = json.loads(path.read_text())
    del body["public"]
    path.write_text(json.dumps(body))


def test_currency_report__everything_current__every_action_is_none(tmp_path):
    _fetched_everything(tmp_path)
    report = currency.currency_report(tmp_path, opener=_served())
    assert {name: entry["action"] for name, entry in report.items()} == {
        "attack": "none",
        "ctid": "none",
        "catalog": "none",
        "disa": "none",
    }
    assert "built" not in report["attack"]


def test_currency_report__disa__reads_the_catalog_and_heads(tmp_path):
    _fetched_everything(tmp_path)
    opener = _Opener({**_public_bodies(), **_disa_bodies("U_Foo_V1R1_STIG.zip")})
    report = currency.currency_report(tmp_path, opener=opener)
    assert report["disa"]["action"] == "refresh"
    assert report["disa"]["new"] == ["U_Foo_V1R1_STIG.zip"]
    assert _CATALOG_POST in opener.requested


def test_currency_report__manifest_without_public_section__asks_for_a_refresh_not_a_crash(tmp_path):
    # The catalog on disk matches upstream's blob sha, so only the missing record can make it
    # read "refresh"; a sha comparison alone would call it current and never record it.
    _manifest_without_public_records(tmp_path)
    assert (tmp_path / fetch._TARGET_FILENAMES["catalog"]).is_file()
    report = currency.currency_report(tmp_path, opener=_served())
    assert report["attack"] == {"upstream": "19.2", "downloaded": None, "action": "refresh"}
    assert report["ctid"] == {"upstream": "16.1", "downloaded": None, "action": "refresh"}
    assert report["catalog"] == {"upstream_changed": False, "downloaded": None, "action": "refresh"}


def test_currency_report__catalog_unrecorded_but_built__asks_for_a_refresh_not_an_ingest(tmp_path):
    # --check passes kb_meta. An unrecorded catalog must read "refresh" even when a build is
    # known: "ingest" would be advice that no ingest can clear.
    _manifest_without_public_records(tmp_path)
    report = currency.currency_report(tmp_path, kb_meta={"catalog": {"version": "5.2.0"}}, opener=_served())
    assert report["catalog"]["action"] == "refresh"


def test_currency_report__upgraded_manifest_after_one_refresh__catalog_reports_nothing_to_do(tmp_path, capsys):
    _manifest_without_public_records(tmp_path)
    fetch._run_refresh(tmp_path, 0, opener=_served())
    assert fetch.read_manifest(tmp_path)["public"]["catalog"]["version"] == "5.2.0"
    kb_meta = {
        "attack": {"version": "19.2"},
        "ctid_attack_version": {"version": "16.1"},
        "catalog": {"version": "5.2.0"},
    }
    report = currency.currency_report(tmp_path, kb_meta=kb_meta, opener=_served())
    assert {name: entry["action"] for name, entry in report.items()} == {
        "attack": "none",
        "ctid": "none",
        "catalog": "none",
        "disa": "none",
    }


def test_currency_report__github_rate_limited__that_source_is_unknown_with_the_reason(tmp_path):
    # A rate limit (HTTP 403) is one source unknown with its reason, never a crash, and it
    # leaves every other source's entry alone.
    _fetched_everything(tmp_path)
    limited = urllib.error.HTTPError(upstream.CTID_LISTING_URL, 403, "rate limit exceeded", {}, None)
    report = currency.currency_report(tmp_path, opener=_served(**{upstream.CTID_LISTING_URL: limited}))
    assert report["ctid"]["status"] == "unknown"
    assert "403" in report["ctid"]["reason"]
    assert report["attack"]["action"] == "none"


def test_currency_report__downloaded_newer_than_built__action_is_ingest(tmp_path):
    _fetched_everything(tmp_path)
    kb_meta = {
        "attack": {"version": "19.1"},
        "ctid_attack_version": {"version": "16.1"},
        "catalog": {"version": "5.2.0"},
    }
    report = currency.currency_report(tmp_path, kb_meta=kb_meta, opener=_served())
    assert report["attack"] == {"upstream": "19.2", "downloaded": "19.2", "built": "19.1", "action": "ingest"}
    assert report["ctid"]["action"] == "none"


def test_currency_report__newer_ctid_folder__action_is_refresh(tmp_path):
    _fetched_everything(tmp_path)
    listing = json.dumps([{"name": "attack-19.1", "type": "dir"}, {"name": "attack-16.1", "type": "dir"}]).encode()
    report = currency.currency_report(tmp_path, opener=_served(**{upstream.CTID_LISTING_URL: listing}))
    assert report["ctid"] == {"upstream": "19.1", "downloaded": "16.1", "action": "refresh"}


def test_currency_report__catalog_changed_upstream__action_is_refresh(tmp_path):
    _fetched_everything(tmp_path)
    changed = json.dumps([{"name": upstream.CATALOG_FILE_NAME, "type": "file", "sha": "f" * 40}]).encode()
    report = currency.currency_report(tmp_path, opener=_served(**{upstream.CATALOG_LISTING_URL: changed}))
    assert report["catalog"]["upstream_changed"] is True and report["catalog"]["action"] == "refresh"


def test_currency_report__catalog_downloaded_newer_than_built__action_is_ingest(tmp_path):
    # The catalog has no separate "downloaded newer than upstream" case (upstream_changed is a
    # bool, not a version), so this reaches _catalog's own ingest branch. kb_meta names no
    # ATT&CK or CTID build, so those two read "ingest" as well; the whole dict is asserted so
    # that is stated rather than left unobserved.
    _fetched_everything(tmp_path)
    report = currency.currency_report(tmp_path, kb_meta={"catalog": {"version": "5.1.0"}}, opener=_served())
    assert {name: entry["action"] for name, entry in report.items()} == {
        "attack": "ingest",
        "ctid": "ingest",
        "catalog": "ingest",
        "disa": "none",
    }


def test_public_report__everything_current__reports_only_the_three_public_sources(tmp_path):
    _fetched_everything(tmp_path)
    report = currency.public_report(tmp_path, opener=_served())
    assert set(report) == {"attack", "ctid", "catalog"}
    assert {name: entry["action"] for name, entry in report.items()} == {
        "attack": "none",
        "ctid": "none",
        "catalog": "none",
    }


def test_currency_report__failure_with_a_huge_message__keeps_the_whole_reason_for_the_operator(tmp_path):
    # --check prints the reason; a remedy at the end of a long message must reach the operator.
    def flooding(request, timeout=None):
        raise OSError("x" * 5000 + " Download it by hand.")

    report = currency.currency_report(tmp_path, opener=flooding)
    for entry in report.values():
        assert entry["status"] == "unknown"
        assert entry["reason"] == "OSError: " + "x" * 5000 + " Download it by hand."


def test_currency_report__failure_with_a_short_message__reason_is_whole(tmp_path):
    def refusing(request, timeout=None):
        raise OSError("connection refused")

    report = currency.currency_report(tmp_path, opener=refusing)
    assert report["attack"]["reason"] == "OSError: connection refused"
