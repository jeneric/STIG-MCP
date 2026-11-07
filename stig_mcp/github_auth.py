"""An optional GITHUB_TOKEN, sent to api.github.com and to no other host.

Release assets redirect to other hosts (githubusercontent.com), and urllib copies request
headers onto a redirect, so the redirect handler here removes the token whenever the target
is not the API host over https."""

import os
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

API_HOST = "api.github.com"

RATE_LIMIT_HINT = (
    "Set GITHUB_TOKEN to a fine-grained token with public read-only access to raise the "
    "limit to 5,000 per hour; see "
    'docs/install.md, "GitHub\'s rate limit".'
)

# 10 digits is generous through the year 2286; a longer or non-ASCII-digit value is never a real
# reset time (GitHub sends whole seconds), so it is treated as unknown rather than passed to gmtime.
_RESET_RE = re.compile(r"[0-9]{1,10}", re.ASCII)


def token(environ=None):
    environ = os.environ if environ is None else environ
    return (environ.get("GITHUB_TOKEN") or "").strip() or None


def _is_api_url(url):
    parts = urlsplit(url)
    return parts.scheme == "https" and parts.hostname == API_HOST


def auth_headers(url, environ=None):
    value = token(environ)
    if value is None or not _is_api_url(url):
        return {}
    return {"Authorization": f"Bearer {value}"}


def rate_limited(exc):
    return (
        isinstance(exc, urllib.error.HTTPError)
        and exc.code in (403, 429)
        and exc.headers is not None
        and exc.headers.get("X-RateLimit-Remaining") == "0"
    )


def reset_time(reset):
    """The rate-limit reset header as a UTC date and time, or None when it is absent, too long,
    not all ASCII digits, or too large for this platform's gmtime to accept."""
    if not _RESET_RE.fullmatch(reset or ""):
        return None
    try:
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(int(reset)))
    except (ValueError, OverflowError, OSError):
        return None


class StripAuthOffApi(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: PLR0913
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and not _is_api_url(newurl):
            # Request stores header names capitalized, so remove_header matches "Authorization".
            new.remove_header("Authorization")
        return new
