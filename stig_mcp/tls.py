"""HTTPS for every request the package makes, verified by the operating system's certificate
store rather than by the roots Python's ssl module ships or copies.

A TLS-inspecting proxy's CA is installed by IT in the OS store, which truststore consults
(CryptoAPI on Windows, the Security framework on macOS, OpenSSL with the system bundle on
Linux). There is no fallback to Python's default context: that is the verifier that rejects
such a proxy, so falling back would turn a clear error into the original silent failure.

Where OpenSSL verifies (Linux), the context also accepts a chain anchored on an intermediate CA,
as Python 3.13's default context does; on Windows and macOS the OS verifies, so OpenSSL's flags
stay as truststore leaves them. SSL_CERT_FILE is honored on every platform; SSL_CERT_DIR only
on Linux, because truststore on Windows and macOS sees only anchors loaded from a file."""

import logging
import os
import ssl
import sys
import urllib.request
from pathlib import Path

import truststore

logger = logging.getLogger(__name__)


def context():
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if sys.platform in ("win32", "darwin"):
        _trust_ssl_cert_file(context)
    else:
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return context


def _trust_ssl_cert_file(context):
    # A missing file is ignored, as ssl.get_default_verify_paths() ignores it.
    cafile = os.environ.get("SSL_CERT_FILE")
    if cafile and Path(cafile).is_file():
        try:
            context.load_verify_locations(cafile=cafile)
        except (ssl.SSLError, OSError) as exc:
            # Python's default context and uv also ignore a file they cannot read or parse.
            logger.warning("Ignoring SSL_CERT_FILE %s: %s", cafile, exc)


def opener(*handlers):
    """An open(request, timeout=...) callable, the shape of urllib.request.urlopen."""
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=context()), *handlers).open
