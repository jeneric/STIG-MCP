import re
import ssl
import urllib.request
from pathlib import Path

import pytest
import truststore

from stig_mcp import tls


class _MarkerRedirects(urllib.request.HTTPRedirectHandler):
    # A handler with a protocol method: OpenerDirector keeps only handlers that have one.
    pass


def _https_handlers(open_url):
    return [h for h in open_url.__self__.handlers if isinstance(h, urllib.request.HTTPSHandler)]


def test_context__default__is_a_truststore_context_that_verifies_peer_and_hostname():
    context = tls.context()
    assert isinstance(context, truststore.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_context__linux__accepts_a_chain_anchored_on_an_intermediate(monkeypatch):
    monkeypatch.setattr(tls.sys, "platform", "linux")
    assert tls.context().verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_context__os_verifies__leaves_the_openssl_flags_untouched(monkeypatch, platform):
    monkeypatch.setattr(tls.sys, "platform", platform)
    assert tls.context().verify_flags == truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT).verify_flags


@pytest.fixture
def verify_location_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(truststore.SSLContext, "load_verify_locations", lambda _self, **kwargs: calls.append(kwargs))
    return calls


def test_context__darwin_with_ssl_cert_file__trusts_that_file(monkeypatch, tmp_path, verify_location_calls):
    cafile = tmp_path / "proxy-ca.pem"
    cafile.write_text("not parsed: load_verify_locations is recorded")
    monkeypatch.setattr(tls.sys, "platform", "darwin")
    monkeypatch.setenv("SSL_CERT_FILE", str(cafile))
    tls.context()
    assert verify_location_calls == [{"cafile": str(cafile)}]


def test_context__win32_with_ssl_cert_file_missing__loads_nothing(monkeypatch, tmp_path, verify_location_calls):
    monkeypatch.setattr(tls.sys, "platform", "win32")
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "absent.pem"))
    tls.context()
    assert verify_location_calls == []


def test_context__linux_with_ssl_cert_file__leaves_it_to_openssl(monkeypatch, tmp_path, verify_location_calls):
    cafile = tmp_path / "proxy-ca.pem"
    cafile.write_text("not parsed")
    monkeypatch.setattr(tls.sys, "platform", "linux")
    monkeypatch.setenv("SSL_CERT_FILE", str(cafile))
    tls.context()
    assert verify_location_calls == []


def test_opener__no_extra_handlers__has_exactly_one_https_handler_on_the_truststore_context():
    (https,) = _https_handlers(tls.opener())
    assert isinstance(https._context, truststore.SSLContext)


def test_opener__extra_handler_class__is_installed_beside_the_https_handler():
    open_url = tls.opener(_MarkerRedirects)
    assert any(isinstance(h, _MarkerRedirects) for h in open_url.__self__.handlers)
    assert len(_https_handlers(open_url)) == 1


def test_opener__truststore_cannot_build_a_context__raises_instead_of_falling_back(monkeypatch):
    def refuse(_protocol):
        raise ssl.SSLError("no usable system store")

    monkeypatch.setattr(tls.truststore, "SSLContext", refuse)
    with pytest.raises(ssl.SSLError, match="no usable system store"):
        tls.opener()


PACKAGE = Path(tls.__file__).resolve().parent


# Code shapes only: fetch.py's docstring and tls.py's both name urlopen in prose, legitimately.
_DEFAULT_URLOPEN = re.compile(
    r"or urllib\.request\.urlopen\b|urllib\.request\.urlopen\(|=\s*urllib\.request\.urlopen\b"
)


def test_package__no_module__opens_urls_with_python_default_urlopen():
    offenders = [
        p.relative_to(PACKAGE).as_posix() for p in PACKAGE.rglob("*.py") if _DEFAULT_URLOPEN.search(p.read_text())
    ]
    assert offenders == []


def test_default_urlopen_pattern__matches_the_shapes_it_guards_and_not_prose():
    assert _DEFAULT_URLOPEN.search("    open_url = opener or urllib.request.urlopen\n")
    assert _DEFAULT_URLOPEN.search("urllib.request.urlopen(request)")
    assert _DEFAULT_URLOPEN.search("def f(opener=urllib.request.urlopen):")
    assert not _DEFAULT_URLOPEN.search("patching urllib.request.urlopen or anything else global")
    assert not _DEFAULT_URLOPEN.search("the shape of urllib.request.urlopen.")


def test_package__modules_calling_the_truststore_opener__are_the_five_network_sites():
    users = {p.relative_to(PACKAGE).as_posix() for p in PACKAGE.rglob("*.py") if "tls.opener(" in p.read_text()}
    assert users == {"kb/releases.py", "ingest/fetch.py", "ingest/catalog.py", "ingest/upstream.py"}
