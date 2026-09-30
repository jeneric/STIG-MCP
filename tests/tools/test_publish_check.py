import hashlib
import io
import json
import urllib.error

import pytest

from tools import publish_check

NAME = "io.github.jeneric/stig-mcp"


# The cases below are the registry's own (mcpname.go and its tests): a bare substring
# match would pass every one of the False rows.
@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (f"intro\n<!-- mcp-name: {NAME} -->\n", True),
        (f"mcp-name: {NAME}", True),
        (f"mcp-name: {NAME}\nmore", True),
        (f"<!-- mcp-name: {NAME}-->", True),
        (f"<!-- mcp-name: {NAME}--!>", True),
        (f"<p>mcp-name: {NAME}</p>", True),
        (f"mcp-name: {NAME}-pro", False),
        (f"mcp-name: {NAME}.", False),
        (f"mcp-name: {NAME}_x", False),
        (f"mcp-name: {NAME}-pro and later mcp-name: {NAME} ", True),
        ("no token here", False),
        (f"mcp-name:{NAME}", False),
    ],
)
def test_contains_mcp_name_token__registry_cases__match_the_registry(content, expected):
    assert publish_check.contains_mcp_name_token(content, NAME) is expected


def _dist(tmp_path, files):
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    return tmp_path


def _served(files):
    return [{"filename": name, "digests": {"sha256": hashlib.sha256(data).hexdigest()}} for name, data in files.items()]


def test_digest_mismatches__identical_files__reports_nothing(tmp_path):
    files = {"a-1.whl": b"wheel", "a-1.tar.gz": b"sdist"}
    assert publish_check.digest_mismatches(_served(files), _dist(tmp_path, files)) == []


def test_digest_mismatches__uv_gitignore_in_dist__is_not_a_distribution(tmp_path):
    files = {"a-1.whl": b"wheel"}
    dist = _dist(tmp_path, {**files, ".gitignore": b"*"})
    assert publish_check.digest_mismatches(_served(files), dist) == []


def test_digest_mismatches__one_byte_differs__names_that_file_and_both_digests(tmp_path):
    dist = _dist(tmp_path, {"a-1.whl": b"wheel", "a-1.tar.gz": b"sdist"})
    served = _served({"a-1.whl": b"wheel", "a-1.tar.gz": b"sdisT"})
    problems = publish_check.digest_mismatches(served, dist)
    assert len(problems) == 1
    assert problems[0].startswith("a-1.tar.gz:")
    assert hashlib.sha256(b"sdist").hexdigest() in problems[0]


def test_digest_mismatches__missing_and_extra_files__are_each_named(tmp_path):
    dist = _dist(tmp_path, {"a-1.whl": b"wheel", "a-1.tar.gz": b"sdist"})
    served = _served({"a-1.whl": b"wheel", "a-1-py2.whl": b"other"})
    problems = publish_check.digest_mismatches(served, dist)
    assert problems == ["a-1.tar.gz: built but not served", "a-1-py2.whl: served but not built here"]


class _Opener:
    """Answers each request with the next scripted status; 200 carries `payload` as JSON."""

    def __init__(self, statuses, payload=None):
        self.statuses, self.payload, self.urls = list(statuses), payload or {}, []

    def __call__(self, request, timeout):
        self.urls.append(request.full_url)
        status = self.statuses.pop(0)
        if status != 200:
            raise urllib.error.HTTPError(request.full_url, status, "status", {}, None)
        return io.BytesIO(json.dumps(self.payload).encode())


def _poll(monkeypatch, attempts, delay):
    monkeypatch.setattr(publish_check, "POLL_ATTEMPTS", attempts)
    monkeypatch.setattr(publish_check, "POLL_DELAY", delay)


def test_fetch_release__not_yet_indexed_then_indexed__returns_the_release(monkeypatch):
    _poll(monkeypatch, 5, 7)
    opener = _Opener([404, 404, 200], {"urls": []})
    sleeps = []
    release = publish_check.fetch_release(
        "https://test.pypi.org", "stig-mcp", "0.1.0.dev101", opener=opener, sleep=sleeps.append
    )
    assert release == {"urls": []}
    assert opener.urls == ["https://test.pypi.org/pypi/stig-mcp/0.1.0.dev101/json"] * 3
    assert sleeps == [7, 7]


def test_fetch_release__never_indexed__returns_none_after_every_attempt(monkeypatch):
    _poll(monkeypatch, 3, 0)
    opener = _Opener([404] * 3)
    assert publish_check.fetch_release("https://test.pypi.org", "p", "1", opener=opener, sleep=lambda _s: None) is None
    assert len(opener.urls) == 3


def test_fetch_release__server_error__raises_instead_of_retrying(monkeypatch):
    _poll(monkeypatch, 3, 0)
    opener = _Opener([503, 200])
    with pytest.raises(urllib.error.HTTPError):
        publish_check.fetch_release("https://test.pypi.org", "p", "1", opener=opener, sleep=lambda _s: None)
    assert len(opener.urls) == 1


def test_fetch_release__plain_http_index__is_refused_before_any_request():
    opener = _Opener([200])
    with pytest.raises(ValueError, match="https"):
        publish_check.fetch_release("http://test.pypi.org", "p", "1", opener=opener, sleep=lambda _s: None)
    assert opener.urls == []


def _stub_server(monkeypatch):
    # main reads server.json through _server; stub it so the test does not depend on the file.
    monkeypatch.setattr(publish_check, "_server", lambda: {"name": NAME, "packages": [{"identifier": "stig-mcp"}]})


def _run_main(monkeypatch, tmp_path, description, served_bytes=b"wheel"):
    _stub_server(monkeypatch)
    dist = _dist(tmp_path, {"stig_mcp-1.whl": b"wheel"})
    release = {"info": {"description": description}, "urls": _served({"stig_mcp-1.whl": served_bytes})}
    monkeypatch.setattr(publish_check, "fetch_release", lambda *_args, **_kwargs: release)
    return publish_check.main(["--index-url", "https://test.pypi.org", "--version", "1", "--dist", str(dist)])


def test_main__served_build_with_the_token__exits_zero(monkeypatch, tmp_path):
    assert _run_main(monkeypatch, tmp_path, f"<!-- mcp-name: {NAME} -->") == 0


def test_main__token_missing__exits_one_and_says_what_the_registry_will_reject(monkeypatch, tmp_path, capsys):
    assert _run_main(monkeypatch, tmp_path, "a README without it") == 1
    assert f"mcp-name: {NAME}" in capsys.readouterr().err


def test_main__served_bytes_differ__exits_one(monkeypatch, tmp_path):
    assert _run_main(monkeypatch, tmp_path, f"mcp-name: {NAME}", served_bytes=b"other") == 1


def test_main__version_never_indexed__exits_one(monkeypatch, tmp_path, capsys):
    _stub_server(monkeypatch)
    monkeypatch.setattr(publish_check, "fetch_release", lambda *_args, **_kwargs: None)
    assert publish_check.main(["--version", "9", "--dist", str(tmp_path)]) == 1
    assert "9" in capsys.readouterr().err
