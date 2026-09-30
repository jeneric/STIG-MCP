import io
import json

import pytest

from stig_mcp.ingest import upstream


class _Opener:
    """Stands in for urllib.request.urlopen: bytes, a response object, or an exception to raise."""

    def __init__(self, bodies):
        self.bodies = bodies
        self.requested = []

    def __call__(self, request, timeout=None):
        self.requested.append(request.full_url)
        body = self.bodies[request.full_url]
        if isinstance(body, Exception):
            raise body
        return io.BytesIO(body)


def _index(*versions):
    """An index.json body listing Enterprise versions in exactly the order given."""
    return {
        "collections": [
            {"name": "Mobile ATT&CK", "versions": [{"version": "99.0", "url": "https://example.invalid/x"}]},
            {
                "name": "Enterprise ATT&CK",
                "versions": [
                    {
                        "version": v,
                        "url": f"{upstream.ATTACK_URL_PREFIX}master/enterprise-attack/enterprise-attack-{v}.json",
                        "modified": f"2026-0{i + 1}-15T14:00:00.188Z",
                    }
                    for i, v in enumerate(versions)
                ],
            },
        ]
    }


def test_parse_attack_index__lower_version_listed_first__picks_the_numerically_highest():
    # Listed low to high so "take the first entry" (what the live file happens to allow) fails.
    parsed = upstream.parse_attack_index(_index("9.0", "16.1", "19.2"))
    assert parsed.latest.version == "19.2"
    assert parsed.latest.url.endswith("enterprise-attack-19.2.json")


def test_parse_attack_index__release_dates__keyed_by_version_as_date_part():
    parsed = upstream.parse_attack_index(_index("16.1", "19.2"))
    assert parsed.release_dates == {"16.1": "2026-01-15", "19.2": "2026-02-15"}


def test_parse_attack_index__malformed_version_entry__is_skipped_not_fatal():
    doc = _index("19.1")
    doc["collections"][1]["versions"].append({"version": "20.0; rm -rf", "url": "https://example.invalid"})
    assert upstream.parse_attack_index(doc).latest.version == "19.1"


def test_parse_attack_index__no_version_entry_in_major_minor_form__raises_upstream_error():
    doc = _index()
    doc["collections"][1]["versions"] = [{"version": "20.0; rm -rf", "url": "https://example.invalid"}]
    with pytest.raises(upstream.UpstreamError, match="MAJOR.MINOR"):
        upstream.parse_attack_index(doc)


def test_parse_attack_index__no_enterprise_collection__raises_upstream_error():
    with pytest.raises(upstream.UpstreamError, match="Enterprise ATT&CK"):
        upstream.parse_attack_index({"collections": []})


def test_version_key__two_digit_minor_and_major__orders_numerically():
    assert upstream.version_key("9.0") < upstream.version_key("16.1") < upstream.version_key("16.10")


def test_date_part__not_a_date__returns_none():
    assert upstream.date_part("yesterday") is None
    assert upstream.date_part(None) is None


def test_attack_latest__served_index__requests_only_the_index_url():
    opener = _Opener({upstream.ATTACK_INDEX_URL: json.dumps(_index("19.1", "19.2")).encode()})
    assert upstream.attack_latest(opener).latest.version == "19.2"
    assert opener.requested == [upstream.ATTACK_INDEX_URL]


def test_get_json__not_json__raises_upstream_error_naming_the_url():
    opener = _Opener({upstream.ATTACK_INDEX_URL: b"<html>rate limited</html>"})
    with pytest.raises(upstream.UpstreamError, match="index.json"):
        upstream.get_json(upstream.ATTACK_INDEX_URL, opener)


def _dir(name):
    return {"name": name, "type": "dir", "sha": "0" * 40}


def test_parse_ctid_listing__newest_folder_listed_first__still_picks_the_highest_version():
    # Newest first so "take the last entry" fails; a stray file and a non-matching dir are ignored.
    listing = [_dir("attack-16.1"), _dir("attack-9.0"), {"name": "README.md", "type": "file"}, _dir("drafts")]
    release = upstream.parse_ctid_listing(listing)
    assert release.attack_version == "16.1"
    assert release.folder == "attack-16.1"
    assert release.url == upstream.CTID_FILE_URL.format(folder="attack-16.1")


def test_parse_ctid_listing__no_attack_folder__raises_upstream_error():
    with pytest.raises(upstream.UpstreamError, match="attack-"):
        upstream.parse_ctid_listing([_dir("drafts")])


def test_parse_catalog_listing__catalog_present__returns_its_blob_sha():
    sha = "81c55f5c652bf2c6ccd5de0afe3ebe4618c6af91"
    listing = [
        {"name": "other.json", "type": "file", "sha": "1" * 40},
        {"name": upstream.CATALOG_FILE_NAME, "type": "file", "sha": sha},
    ]
    assert upstream.parse_catalog_listing(listing) == sha


def test_parse_catalog_listing__catalog_missing__raises_upstream_error_naming_it():
    with pytest.raises(upstream.UpstreamError, match=upstream.CATALOG_FILE_NAME):
        upstream.parse_catalog_listing([])


def test_git_blob_sha__known_content__matches_git_hash_object(tmp_path):
    # `printf 'hello\n' | git hash-object --stdin` prints this value.
    path = tmp_path / "f"
    path.write_bytes(b"hello\n")
    assert upstream.git_blob_sha(path) == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_ctid_latest__served_listing__sends_the_github_accept_header():
    seen = {}

    def opener(request, timeout=None):
        seen["accept"] = request.get_header("Accept")
        return io.BytesIO(json.dumps([_dir("attack-16.1")]).encode())

    assert upstream.ctid_latest(opener).attack_version == "16.1"
    assert seen["accept"] == upstream.GITHUB_ACCEPT


def test_catalog_state__served_listing__sends_the_github_accept_header():
    seen = {}
    sha = "81c55f5c652bf2c6ccd5de0afe3ebe4618c6af91"

    def opener(request, timeout=None):
        seen["accept"] = request.get_header("Accept")
        return io.BytesIO(json.dumps([{"name": upstream.CATALOG_FILE_NAME, "type": "file", "sha": sha}]).encode())

    assert upstream.catalog_state(opener) == sha
    assert seen["accept"] == upstream.GITHUB_ACCEPT
