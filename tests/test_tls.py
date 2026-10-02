import ssl
import urllib.request

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
