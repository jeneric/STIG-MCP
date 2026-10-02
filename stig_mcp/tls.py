"""HTTPS for every request the package makes, verified by the operating system's certificate
store rather than by the roots Python's ssl module ships or copies.

A TLS-inspecting proxy's CA is installed by IT in the OS store, which truststore consults
(CryptoAPI on Windows, the Security framework on macOS, OpenSSL with the system bundle on
Linux). There is no fallback to Python's default context: that is the verifier that rejects
such a proxy, so falling back would turn a clear error into the original silent failure."""

import ssl
import urllib.request

import truststore


def context():
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def opener(*handlers):
    """An open(request, timeout=...) callable, the shape of urllib.request.urlopen."""
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=context()), *handlers).open
