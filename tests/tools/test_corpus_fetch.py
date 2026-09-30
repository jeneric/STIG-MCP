import hashlib
import json
import signal

import pytest

from tools import corpus_fetch, corpus_manifest

PAYLOAD = b"PK\x03\x04 pretend archive"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


@pytest.fixture(autouse=True)
def _restore_the_sigterm_handler():
    """main() installs a SIGTERM handler and never restores it, which is correct for the
    real CLI process but leaks process-wide once any test here calls main(): every test
    that runs afterward inherits _raise_keyboard_interrupt in place of whatever SIGTERM
    disposition the process actually had, so a runner timeout, a CI cancel, or any real
    kill raises KeyboardInterrupt inside whichever test is mid-flight instead of
    terminating the process. The two SIGTERM tests below restore what they captured, but
    without this fixture an earlier main() call may already have replaced it under
    pytest-randomly, so their restore would put the pollution back."""
    original_handler = signal.getsignal(signal.SIGTERM)
    yield
    signal.signal(signal.SIGTERM, original_handler)


def _manifest(*names_and_tiers):
    return {
        "source_url": "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/",
        "entries": [
            {"name": name, "href": name, "tier": tier, "sha256": None, "size": None} for name, tier in names_and_tiers
        ],
    }


class _Response:
    def __init__(self, payload):
        self._payload = payload

    def read(self, _size=None):
        payload, self._payload = self._payload, b""
        return payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _opener(seen, timeouts=None):
    def opener(request, timeout=None):
        seen.append(request.full_url)
        if timeouts is not None:
            timeouts.append(timeout)
        return _Response(PAYLOAD)

    return opener


def _stalling_opener(failures, seen):
    """Raises TimeoutError for the first `failures` calls, the way a silent socket does.

    Every attempt appends to `seen`, so the caller counts attempts by its length."""

    def opener(request, timeout=None):
        seen.append(request.full_url)
        if len(seen) <= failures:
            raise TimeoutError("the read timed out")
        return _Response(PAYLOAD)

    return opener


def test_stage__a_benchmark_tier_entry__downloads_it_and_records_its_checksum(tmp_path):
    manifest = _manifest(("U_Apple_macOS_15_V1R7_STIG.zip", corpus_manifest.BENCHMARK))
    seen = []
    result = corpus_fetch.stage(
        manifest, tmp_path, tiers=(corpus_manifest.BENCHMARK,), opener=_opener(seen), sleep=lambda _s: None
    )
    assert result["downloaded"] == 1
    assert (tmp_path / "U_Apple_macOS_15_V1R7_STIG.zip").read_bytes() == PAYLOAD
    assert manifest["entries"][0]["sha256"] == DIGEST
    assert manifest["entries"][0]["size"] == len(PAYLOAD)


def test_stage__a_tier_not_requested__is_not_downloaded(tmp_path):
    manifest = _manifest(("OneDrive_1_7-10-2026.zip", corpus_manifest.JUNK))
    seen = []
    result = corpus_fetch.stage(
        manifest, tmp_path, tiers=(corpus_manifest.BENCHMARK,), opener=_opener(seen), sleep=lambda _s: None
    )
    assert result["downloaded"] == 0
    assert seen == []
    assert list(tmp_path.iterdir()) == []


def test_stage__a_file_already_matching_its_checksum__is_skipped_without_a_request(tmp_path):
    manifest = _manifest(("U_Apple_macOS_15_V1R7_STIG.zip", corpus_manifest.BENCHMARK))
    manifest["entries"][0]["sha256"] = DIGEST
    (tmp_path / "U_Apple_macOS_15_V1R7_STIG.zip").write_bytes(PAYLOAD)
    seen = []
    result = corpus_fetch.stage(
        manifest, tmp_path, tiers=(corpus_manifest.BENCHMARK,), opener=_opener(seen), sleep=lambda _s: None
    )
    assert result == {"downloaded": 0, "skipped": 1, "bytes": 0}
    assert seen == []


def test_stage__a_file_whose_checksum_no_longer_matches__is_downloaded_again(tmp_path):
    manifest = _manifest(("U_Apple_macOS_15_V1R7_STIG.zip", corpus_manifest.BENCHMARK))
    manifest["entries"][0]["sha256"] = DIGEST
    (tmp_path / "U_Apple_macOS_15_V1R7_STIG.zip").write_bytes(b"stale bytes")
    seen = []
    result = corpus_fetch.stage(
        manifest, tmp_path, tiers=(corpus_manifest.BENCHMARK,), opener=_opener(seen), sleep=lambda _s: None
    )
    assert result["downloaded"] == 1
    assert (tmp_path / "U_Apple_macOS_15_V1R7_STIG.zip").read_bytes() == PAYLOAD


def test_stage__a_file_on_disk_with_no_recorded_checksum__is_downloaded_again(tmp_path):
    # The skip condition short-circuits on entry["sha256"] first, so a file already correct
    # on disk is still re-fetched if the manifest never recorded a checksum for it: nothing
    # vouches for bytes nobody has verified, whatever they happen to contain.
    manifest = _manifest(("U_Apple_macOS_15_V1R7_STIG.zip", corpus_manifest.BENCHMARK))
    (tmp_path / "U_Apple_macOS_15_V1R7_STIG.zip").write_bytes(PAYLOAD)
    seen = []
    result = corpus_fetch.stage(
        manifest, tmp_path, tiers=(corpus_manifest.BENCHMARK,), opener=_opener(seen), sleep=lambda _s: None
    )
    assert result["downloaded"] == 1
    assert seen
    assert manifest["entries"][0]["sha256"] == DIGEST


def test_stage__more_than_one_download__waits_between_requests(tmp_path):
    # No Crawl-delay is published, so the tool picks a conservative one itself rather than
    # issuing back-to-back requests at a DoD host.
    manifest = _manifest(
        ("U_Apple_macOS_15_V1R7_STIG.zip", corpus_manifest.BENCHMARK),
        ("U_Kubernetes_V2R6_STIG.zip", corpus_manifest.BENCHMARK),
    )
    waits = []
    corpus_fetch.stage(
        manifest, tmp_path, tiers=(corpus_manifest.BENCHMARK,), opener=_opener([]), sleep=waits.append, delay=2.5
    )
    assert waits == [2.5, 2.5]


def test_stage__a_cui_entry_smuggled_into_a_manifest__is_refused(tmp_path):
    # tier_of refuses CUI at manifest time, so reaching stage() means the manifest was
    # hand-edited. Refuse again rather than trusting an input file.
    manifest = _manifest(("CUI_Restricted_V1R1_STIG.zip", corpus_manifest.BENCHMARK))
    with pytest.raises(ValueError) as excinfo:
        corpus_fetch.stage(
            manifest, tmp_path, tiers=(corpus_manifest.BENCHMARK,), opener=_opener([]), sleep=lambda _s: None
        )
    assert "CAC" in str(excinfo.value)


def test_stage__a_cui_href_diverged_from_an_innocuous_name__is_refused(tmp_path):
    # The name-only guard passes an innocuous name; only checking the resolved URL, which is
    # built from href, catches a hand-edited manifest where the two have diverged.
    manifest = _manifest(("Innocuous_Name_V1R1_STIG.zip", corpus_manifest.BENCHMARK))
    manifest["entries"][0]["href"] = "CUI_Restricted_V1R1_STIG.zip"
    with pytest.raises(ValueError) as excinfo:
        corpus_fetch.stage(
            manifest, tmp_path, tiers=(corpus_manifest.BENCHMARK,), opener=_opener([]), sleep=lambda _s: None
        )
    assert "CAC" in str(excinfo.value)


def test_stage__an_entry_whose_name_escapes_the_destination__is_refused(tmp_path):
    manifest = _manifest(("../escape.zip", corpus_manifest.BENCHMARK))
    with pytest.raises(ValueError) as excinfo:
        corpus_fetch.stage(
            manifest, tmp_path, tiers=(corpus_manifest.BENCHMARK,), opener=_opener([]), sleep=lambda _s: None
        )
    assert "outside" in str(excinfo.value).lower()


def test_main__stage_raises_partway__still_persists_the_progress_made_before_the_failure(monkeypatch, tmp_path):
    # The manifest must be written even when stage() raises, or one transient HTTP error or
    # one Ctrl-C discards every checksum recorded that session and the next run re-downloads
    # everything. Mimics what a real stage() does:
    # it mutates each entry's checksum in place as it goes, so the first entry is already
    # recorded by the time the second entry's download fails.
    manifest = _manifest(
        ("U_A_STIG.zip", corpus_manifest.BENCHMARK),
        ("U_B_STIG.zip", corpus_manifest.BENCHMARK),
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def failing_stage(loaded_manifest, dest_dir, tiers, delay):
        loaded_manifest["entries"][0]["sha256"] = DIGEST
        loaded_manifest["entries"][0]["size"] = len(PAYLOAD)
        raise TimeoutError("simulated network failure")

    monkeypatch.setattr(corpus_fetch, "stage", failing_stage)
    monkeypatch.setattr(
        "sys.argv",
        ["corpus_fetch", "--manifest", str(manifest_path), "--dest", str(tmp_path / "dest")],
    )

    with pytest.raises(TimeoutError):
        corpus_fetch.main()

    persisted = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert persisted["entries"][0]["sha256"] == DIGEST
    assert persisted["entries"][1]["sha256"] is None


def test_main__a_cli_invocation__installs_a_sigterm_handler_before_staging(monkeypatch, tmp_path):
    # A hard kill (SIGTERM, the default `kill`) has to reach the same code path as Ctrl-C
    # for the finally below to persist the manifest.
    manifest = _manifest(("U_A_STIG.zip", corpus_manifest.BENCHMARK))
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    original_handler = signal.getsignal(signal.SIGTERM)
    installed_during_stage = {}

    def fake_stage(loaded_manifest, dest_dir, tiers, delay):
        installed_during_stage["handler"] = signal.getsignal(signal.SIGTERM)
        return {"downloaded": 0, "skipped": 0, "bytes": 0}

    monkeypatch.setattr(corpus_fetch, "stage", fake_stage)
    monkeypatch.setattr(
        "sys.argv",
        ["corpus_fetch", "--manifest", str(manifest_path), "--dest", str(tmp_path / "dest")],
    )
    try:
        corpus_fetch.main()
    finally:
        signal.signal(signal.SIGTERM, original_handler)

    assert installed_during_stage["handler"] is corpus_fetch._raise_keyboard_interrupt


def test_main__sigterm_arriving_mid_stage__still_persists_the_progress_made_before_it(monkeypatch, tmp_path):
    # Mimics what the OS does on a hard kill: the installed handler fires partway through
    # stage(), after some entries are already recorded, and turns the signal into the same
    # KeyboardInterrupt Ctrl-C already raises so the existing finally still runs. Calls the
    # handler directly rather than sending a real signal, so this cannot kill the runner.
    manifest = _manifest(
        ("U_A_STIG.zip", corpus_manifest.BENCHMARK),
        ("U_B_STIG.zip", corpus_manifest.BENCHMARK),
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    original_handler = signal.getsignal(signal.SIGTERM)

    def killed_mid_stage(loaded_manifest, dest_dir, tiers, delay):
        loaded_manifest["entries"][0]["sha256"] = DIGEST
        loaded_manifest["entries"][0]["size"] = len(PAYLOAD)
        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

    monkeypatch.setattr(corpus_fetch, "stage", killed_mid_stage)
    monkeypatch.setattr(
        "sys.argv",
        ["corpus_fetch", "--manifest", str(manifest_path), "--dest", str(tmp_path / "dest")],
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            corpus_fetch.main()
    finally:
        signal.signal(signal.SIGTERM, original_handler)

    persisted = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert persisted["entries"][0]["sha256"] == DIGEST
    assert persisted["entries"][1]["sha256"] is None


def test_main__a_cli_invocation__stages_the_manifest_and_prints_the_counts(monkeypatch, tmp_path, capsys):
    manifest = _manifest(("U_Apple_macOS_15_V1R7_STIG.zip", corpus_manifest.BENCHMARK))
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    dest = tmp_path / "dest"
    calls = {}

    def fake_stage(loaded_manifest, dest_dir, tiers, delay):
        calls["manifest"] = loaded_manifest
        calls["dest_dir"] = dest_dir
        calls["tiers"] = tiers
        calls["delay"] = delay
        return {"downloaded": 1, "skipped": 0, "bytes": 42}

    monkeypatch.setattr(corpus_fetch, "stage", fake_stage)
    monkeypatch.setattr(
        "sys.argv",
        ["corpus_fetch", "--manifest", str(manifest_path), "--dest", str(dest)],
    )

    corpus_fetch.main()

    captured = capsys.readouterr()
    assert "Staged 1 file(s), skipped 0, 42 bytes" in captured.out
    assert calls["dest_dir"] == str(dest)
    assert calls["tiers"] == (corpus_manifest.BENCHMARK,)
    assert calls["delay"] == 1.0
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["entries"] == manifest["entries"]


def test_main__an_explicit_tier_flag__overrides_the_benchmark_default(monkeypatch, tmp_path, capsys):
    manifest = _manifest(("U_SRG-STIG_Library_July_2026.zip", corpus_manifest.COMPILATION))
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    calls = {}

    def fake_stage(loaded_manifest, dest_dir, tiers, delay):
        calls["tiers"] = tiers
        return {"downloaded": 0, "skipped": 0, "bytes": 0}

    monkeypatch.setattr(corpus_fetch, "stage", fake_stage)
    monkeypatch.setattr(
        "sys.argv",
        [
            "corpus_fetch",
            "--manifest",
            str(manifest_path),
            "--dest",
            str(tmp_path / "dest"),
            "--tier",
            corpus_manifest.COMPILATION,
        ],
    )

    corpus_fetch.main()

    assert calls["tiers"] == (corpus_manifest.COMPILATION,)


def test_stage__a_download__is_given_a_socket_timeout(tmp_path):
    # urlopen without a timeout inherits socket.getdefaulttimeout(), which is None, so a
    # connection that goes silent mid-run blocks forever. Dropping the timeout argument from
    # _download fails this test.
    manifest = _manifest(("U_Apple_macOS_15_V1R7_STIG.zip", corpus_manifest.BENCHMARK))
    timeouts = []
    corpus_fetch.stage(
        manifest,
        tmp_path,
        tiers=(corpus_manifest.BENCHMARK,),
        opener=_opener([], timeouts=timeouts),
        sleep=lambda _s: None,
    )
    assert timeouts == [corpus_fetch._TIMEOUT]
    assert corpus_fetch._TIMEOUT > 0


def test_stage__a_connection_that_stalls_once__is_retried_and_still_staged(tmp_path):
    manifest = _manifest(("U_Apple_macOS_15_V1R7_STIG.zip", corpus_manifest.BENCHMARK))
    attempts = []
    result = corpus_fetch.stage(
        manifest,
        tmp_path,
        tiers=(corpus_manifest.BENCHMARK,),
        opener=_stalling_opener(1, attempts),
        sleep=lambda _s: None,
    )
    assert len(attempts) == 2
    assert result["downloaded"] == 1
    assert manifest["entries"][0]["sha256"] == DIGEST


def test_stage__a_connection_that_never_recovers__gives_up_rather_than_hanging(tmp_path):
    manifest = _manifest(("U_Apple_macOS_15_V1R7_STIG.zip", corpus_manifest.BENCHMARK))
    attempts = []
    with pytest.raises(TimeoutError):
        corpus_fetch.stage(
            manifest,
            tmp_path,
            tiers=(corpus_manifest.BENCHMARK,),
            opener=_stalling_opener(corpus_fetch._ATTEMPTS, attempts),
            sleep=lambda _s: None,
        )
    assert len(attempts) == corpus_fetch._ATTEMPTS
    # The entry keeps its absent checksum, so a resumed run re-downloads rather than
    # trusting whatever bytes reached disk before the stall.
    assert manifest["entries"][0]["sha256"] is None


def test_stage__a_retry__waits_the_politeness_delay_before_trying_again(tmp_path):
    manifest = _manifest(("U_Apple_macOS_15_V1R7_STIG.zip", corpus_manifest.BENCHMARK))
    waits = []
    corpus_fetch.stage(
        manifest,
        tmp_path,
        tiers=(corpus_manifest.BENCHMARK,),
        opener=_stalling_opener(1, []),
        sleep=waits.append,
        delay=2.5,
    )
    assert waits == [2.5, 2.5]
