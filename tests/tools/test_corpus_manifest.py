import copy
import json
import urllib.parse

import pytest

from stig_mcp.ingest import catalog
from tools import corpus_manifest


@pytest.mark.parametrize(
    "name,expected",
    [
        # Real filenames taken verbatim from the published directory listing.
        ("U_A10_Networks_ADC_Y24M07_STIG.zip", corpus_manifest.BENCHMARK),
        ("U_Apple_macOS_15_V1R7_STIG.zip", corpus_manifest.BENCHMARK),
        ("U_Kubernetes_V2R6_STIG.zip", corpus_manifest.BENCHMARK),
        ("U_SRG-STIG_Library_July_2026.zip", corpus_manifest.COMPILATION),
        ("U_Rev_4_SRG-STIG_Sunset_Compilation.zip", corpus_manifest.COMPILATION),
        ("U_MS_Windows_11_V2R9_STIG_SCAP_1-3_Benchmark.zip", corpus_manifest.ADVERSARIAL),
        ("U_CAN_Ubuntu_22-04_LTS_V2R9_STIG_Ansible.zip", corpus_manifest.ADVERSARIAL),
        ("U_CAN_Ubuntu_24-04_LTS_V1R6_STIG_Chef.zip", corpus_manifest.ADVERSARIAL),
        ("U_MS_Windows_Server_2016_V1R3_STIG_PowerShell_DSC.zip", corpus_manifest.ADVERSARIAL),
        ("U_AAA_Services_V2R2_SRG.zip", corpus_manifest.ADVERSARIAL),
        ("U_Intune_Policy_Package_July_2026.zip", corpus_manifest.ADVERSARIAL),
        ("U_July 2024 Quarterly Release Automated Benchmarks.zip", corpus_manifest.ADVERSARIAL),
        ("OneDrive_1_7-10-2026.zip", corpus_manifest.JUNK),
        ("CCI_List.zip", corpus_manifest.JUNK),
        ("RPM-GPG-KEY-SCC-5.11", None),
        ("SCC_5.11_UNIX_Remote_Scanning_Plugin.scc", None),
    ],
)
def test_tier_of__a_published_filename__lands_in_the_right_tier(name, expected):
    assert corpus_manifest.tier_of(name) == expected


def test_tier_of__a_cui_filename__refuses_with_the_credential_reason():
    with pytest.raises(ValueError) as excinfo:
        corpus_manifest.tier_of("CUI_Some_Restricted_V1R1_STIG.zip")
    message = str(excinfo.value)
    assert "CUI" in message
    assert "CAC" in message


@pytest.mark.parametrize(
    "name",
    ["U_Rev_4_SRG-STIG_Sunset_Compilation.zip", "U_SRG-STIG_Library_July_2026.zip"],
)
def test_tier_of__a_compilation_named_with_srg_stig__is_a_compilation_not_adversarial(name):
    # Both compilations are named with the hyphenated pair "SRG-STIG". That contains "_srg",
    # which is an adversarial marker, and it does NOT contain "_stig", because the g is
    # followed by a hyphen. So both the marker check and the "_stig" check get these wrong,
    # and the compilation check has to run before either. Getting this backwards discards
    # the two richest sources in the corpus as requirements guides.
    assert corpus_manifest.tier_of(name) == corpus_manifest.COMPILATION


def _base(*entries):
    return {"source_url": catalog.ZIP_BASE, "entries": [dict(entry) for entry in entries], "cui_skipped": 0}


def _staged(name, size=100, sha256="aa", href=None):
    return {"name": name, "href": href or name, "tier": corpus_manifest.BENCHMARK, "sha256": sha256, "size": size}


def _cat(name):
    return catalog.Entry(name=name, href=urllib.parse.quote(name), date="2026-11-01", size_bytes=None)


def _merged(manifest, name):
    return next(entry for entry in manifest["entries"] if entry["name"] == name)


def test_merge__a_base_only_entry__is_kept_unchanged():
    base = _base(_staged("U_MarkLogic_Server_v9_V3R2_STIG.zip", size=10))
    manifest, report = corpus_manifest.merge(base, [], {})
    assert manifest["entries"] == [_staged("U_MarkLogic_Server_v9_V3R2_STIG.zip", size=10)]
    assert report["kept"] == 1


def test_merge__a_new_catalog_name__is_added_tiered_with_no_checksum():
    manifest, report = corpus_manifest.merge(_base(), [_cat("U_Kubernetes_V2R6_STIG.zip")], {})
    assert manifest["entries"] == [
        {
            "name": "U_Kubernetes_V2R6_STIG.zip",
            "href": "U_Kubernetes_V2R6_STIG.zip",
            "tier": corpus_manifest.BENCHMARK,
            "sha256": None,
            "size": None,
        }
    ]
    assert report["added"] == ["U_Kubernetes_V2R6_STIG.zip"]


def test_merge__a_shared_name_whose_length_changed__clears_sha256_and_size():
    name = "U_RHEL_9_V2R10_STIG.zip"
    manifest, report = corpus_manifest.merge(_base(_staged(name)), [_cat(name)], {name: 101})
    entry = _merged(manifest, name)
    assert entry["sha256"] is None
    assert entry["size"] is None
    assert report["restaged"] == [name]
    assert report["added"] == []


def test_merge__a_shared_name_whose_length_matches__keeps_sha256_and_size():
    name = "U_RHEL_9_V2R10_STIG.zip"
    manifest, report = corpus_manifest.merge(_base(_staged(name)), [_cat(name)], {name: 100})
    assert _merged(manifest, name) == _staged(name)
    assert report["restaged"] == []


def test_merge__a_shared_name_never_staged__is_kept_with_no_restage():
    name = "U_RHEL_9_V2R10_STIG.zip"
    unstaged = _staged(name, size=None, sha256=None)
    manifest, report = corpus_manifest.merge(_base(unstaged), [_cat(name)], {})
    assert _merged(manifest, name) == unstaged
    assert report["restaged"] == []


def test_merge__a_shared_name_with_a_space__keeps_the_base_href():
    name = "U_July 2024 Quarterly Release Automated Benchmarks.zip"
    href = "U_July%202024%20Quarterly%20Release%20Automated%20Benchmarks.zip"
    base = _base(_staged(name, href=href))
    manifest, _report = corpus_manifest.merge(base, [_cat(name)], {name: 100})
    assert _merged(manifest, name)["href"] == href


def test_merge__a_cui_catalog_name__is_skipped_and_counted():
    manifest, report = corpus_manifest.merge(_base(), [_cat("CUI_Restricted_V1R1_STIG.zip")], {})
    assert manifest["entries"] == []
    assert manifest["cui_skipped"] == 1
    assert report["added"] == []


def test_merge__a_non_archive_catalog_name__is_left_out():
    manifest, report = corpus_manifest.merge(_base(), [_cat("RPM-GPG-KEY-SCC-5.11")], {})
    assert manifest["entries"] == []
    assert report["added"] == []


def test_merge__unsorted_inputs__writes_entries_sorted_by_name():
    base = _base(_staged("U_Zebra_V1R1_STIG.zip"), _staged("U_Beta_V1R1_STIG.zip"))
    catalog_entries = [_cat("U_Yak_V1R1_STIG.zip"), _cat("U_Alpha_V1R1_STIG.zip")]
    manifest, _report = corpus_manifest.merge(base, catalog_entries, {})
    assert [entry["name"] for entry in manifest["entries"]] == [
        "U_Alpha_V1R1_STIG.zip",
        "U_Beta_V1R1_STIG.zip",
        "U_Yak_V1R1_STIG.zip",
        "U_Zebra_V1R1_STIG.zip",
    ]


def test_merge__a_restage__does_not_mutate_the_base():
    name = "U_RHEL_9_V2R10_STIG.zip"
    base = _base(_staged(name))
    before = copy.deepcopy(base)
    corpus_manifest.merge(base, [_cat(name), _cat("U_Kubernetes_V2R6_STIG.zip")], {name: 101})
    assert base == before


def test_merge__the_base_source_url__is_carried_over():
    manifest, _report = corpus_manifest.merge(_base(), [], {})
    assert manifest["source_url"] == catalog.ZIP_BASE


class _HeadResponse:
    def __init__(self, length):
        self.headers = {"Content-Length": str(length)}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _recording_opener(seen, length=7):
    def opener(request, timeout=None):
        seen.append(request)
        return _HeadResponse(length)

    return opener


def test_measure__only_staged_shared_names__are_requested():
    staged, unstaged, new = "U_RHEL_9_V2R10_STIG.zip", "U_TOSS_4_V2R2_STIG.zip", "U_Kubernetes_V2R6_STIG.zip"
    base = _base(_staged(staged, size=5), _staged(unstaged, size=None, sha256=None))
    seen, sleeps = [], []
    lengths = corpus_manifest.measure(
        [_cat(staged), _cat(unstaged), _cat(new)], base, _recording_opener(seen), sleep=sleeps.append
    )
    assert lengths == {staged: 7}
    assert [request.full_url for request in seen] == [catalog.ZIP_BASE + staged]
    assert sleeps == [1.0]


def test_measure__the_request__carries_the_corpus_tool_user_agent():
    name = "U_RHEL_9_V2R10_STIG.zip"
    seen = []
    corpus_manifest.measure([_cat(name)], _base(_staged(name)), _recording_opener(seen), sleep=lambda _s: None)
    assert seen[0].get_method() == "HEAD"
    assert seen[0].get_header("User-agent") == corpus_manifest.USER_AGENT


def test_write_manifest__a_manifest__round_trips_as_json(tmp_path):
    manifest = _base(_staged("U_RHEL_9_V2R10_STIG.zip"))
    written = corpus_manifest.write_manifest(manifest, tmp_path / "manifest.json")
    assert json.loads(written.read_text(encoding="utf-8")) == manifest


def test_entry_url__a_manifest_entry__joins_the_href_to_the_source_url():
    entry = _staged("U_July 2024 Quarterly Release Automated Benchmarks.zip", href="U_July%202024.zip")
    assert corpus_manifest.entry_url(_base(entry), entry) == catalog.ZIP_BASE + "U_July%202024.zip"


def _catalog_text(*names):
    rows = [{"DownloadLink": catalog.ZIP_BASE + name, "UploadDate": "2026-11-01", "FileName": name} for name in names]
    return json.dumps({"returnValue": rows})


def _run_main(monkeypatch, tmp_path, base, names, length=100, out=None):  # noqa: PLR0913
    """main() over a base file and a fake catalog, never touching the network."""
    base_path = tmp_path / "base.json"
    base_path.write_text(json.dumps(base), encoding="utf-8")
    out_path = out or tmp_path / "out.json"
    seen = {"catalog_calls": 0}

    def fake_fetch_catalog(opener=None, user_agent=None):
        seen["catalog_calls"] += 1
        seen["user_agent"] = user_agent
        return _catalog_text(*names)

    monkeypatch.setattr(corpus_manifest, "fetch_catalog", fake_fetch_catalog)
    monkeypatch.setattr(corpus_manifest.tls, "opener", lambda: _recording_opener([], length))
    argv = ["corpus_manifest", "--base", str(base_path), "--out", str(out_path), "--delay", "0"]
    monkeypatch.setattr("sys.argv", argv)
    corpus_manifest.main()
    return out_path, seen


def test_main__a_base_and_a_catalog__writes_the_merged_manifest_and_reports_counts(monkeypatch, tmp_path, capsys):
    base = _base(_staged("U_RHEL_9_V2R10_STIG.zip"))
    out_path, _seen = _run_main(monkeypatch, tmp_path, base, ["U_RHEL_9_V2R10_STIG.zip", "U_Kubernetes_V2R6_STIG.zip"])
    names = [entry["name"] for entry in json.loads(out_path.read_text(encoding="utf-8"))["entries"]]
    assert names == ["U_Kubernetes_V2R6_STIG.zip", "U_RHEL_9_V2R10_STIG.zip"]
    printed = capsys.readouterr().out
    assert str(out_path) in printed
    assert "kept 1" in printed
    assert "added 1" in printed
    assert "re-staged 0" in printed


def test_main__a_restaged_name__is_named_in_the_output(monkeypatch, tmp_path, capsys):
    base = _base(_staged("U_RHEL_9_V2R10_STIG.zip", size=100))
    _run_main(monkeypatch, tmp_path, base, ["U_RHEL_9_V2R10_STIG.zip"], length=101)
    printed = capsys.readouterr().out
    assert "re-staged 1" in printed
    assert "U_RHEL_9_V2R10_STIG.zip" in printed


def test_main__the_catalog_request__carries_the_corpus_tool_user_agent(monkeypatch, tmp_path):
    _out, seen = _run_main(monkeypatch, tmp_path, _base(), ["U_Kubernetes_V2R6_STIG.zip"])
    assert seen["user_agent"] == corpus_manifest.USER_AGENT


def test_main__out_is_the_base_by_another_spelling__refuses_before_any_request(monkeypatch, tmp_path, capsys):
    (tmp_path / "sub").mkdir()
    base = _base(_staged("U_RHEL_9_V2R10_STIG.zip"))
    before = json.dumps(base)
    with pytest.raises(SystemExit):
        _run_main(
            monkeypatch, tmp_path, base, ["U_Kubernetes_V2R6_STIG.zip"], out=tmp_path / "sub" / ".." / "base.json"
        )
    assert "is the base manifest" in capsys.readouterr().err
    assert (tmp_path / "base.json").read_text(encoding="utf-8") == before


def test_main__out_is_the_base__never_fetches_the_catalog(monkeypatch, tmp_path):
    monkeypatch.setattr(corpus_manifest, "fetch_catalog", lambda **_kw: pytest.fail("must not be called"))
    base_path = tmp_path / "base.json"
    base_path.write_text(json.dumps(_base()), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["corpus_manifest", "--base", str(base_path), "--out", str(base_path)])
    with pytest.raises(SystemExit):
        corpus_manifest.main()


def test_main__a_base_from_another_source_url__refuses_naming_both_urls(monkeypatch, tmp_path, capsys):
    base = _base()
    base["source_url"] = "https://example.invalid/zips/"
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, tmp_path, base, ["U_Kubernetes_V2R6_STIG.zip"])
    err = capsys.readouterr().err
    assert "https://example.invalid/zips/" in err
    assert catalog.ZIP_BASE in err
    assert not (tmp_path / "out.json").exists()


def test_main__a_head_fails_partway__writes_nothing_and_names_the_file(monkeypatch, tmp_path):
    base = _base(_staged("U_A_V1R1_STIG.zip"), _staged("U_X_V1R1_STIG.zip"))
    calls = []

    def failing_head_length(entry, open_url, user_agent=None):
        calls.append(entry.name)
        if entry.name == "U_X_V1R1_STIG.zip":
            raise RuntimeError(f"The server sent no usable Content-Length for {entry.name}")
        return 100

    monkeypatch.setattr(corpus_manifest, "head_length", failing_head_length)
    with pytest.raises(RuntimeError, match="U_X_V1R1_STIG.zip"):
        _run_main(monkeypatch, tmp_path, base, ["U_A_V1R1_STIG.zip", "U_X_V1R1_STIG.zip"])
    assert calls == ["U_A_V1R1_STIG.zip", "U_X_V1R1_STIG.zip"]
    assert not (tmp_path / "out.json").exists()
