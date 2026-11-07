import email.message
import urllib.error
import urllib.request

import pytest

from stig_mcp import github_auth

OFF_API = "https://release-assets.githubusercontent.com/x"


def _request_with_authorization():
    return urllib.request.Request("https://api.github.com/repos/x/y/releases", headers={"Authorization": "Bearer t0k"})


def _redirect(handler, target):
    return handler.redirect_request(_request_with_authorization(), None, 302, "Found", {}, target)


def _http_error(code, headers):
    message = email.message.Message()
    for name, value in headers.items():
        message[name] = value
    return urllib.error.HTTPError("https://api.github.com/x", code, "msg", message, None)


def test_redirect_handler__stdlib_base_class__copies_authorization_onto_the_redirect():
    new = _redirect(urllib.request.HTTPRedirectHandler(), OFF_API)

    assert new.get_header("Authorization") == "Bearer t0k"


def test_strip_auth_off_api__redirect_to_another_host__drops_authorization():
    new = _redirect(github_auth.StripAuthOffApi(), OFF_API)

    assert new.get_header("Authorization") is None
    assert not new.has_header("Authorization")


def test_strip_auth_off_api__authorization_in_unredirected_headers__drops_it():
    request = urllib.request.Request("https://api.github.com/x")
    request.add_unredirected_header("Authorization", "Bearer t0k")

    new = github_auth.StripAuthOffApi().redirect_request(request, None, 302, "Found", {}, OFF_API)

    assert not new.has_header("Authorization")
    assert "Authorization" not in new.unredirected_hdrs


def test_strip_auth_off_api__redirect_within_api_host__keeps_authorization():
    new = _redirect(github_auth.StripAuthOffApi(), "https://api.github.com/repositories/1/releases")

    assert new.get_header("Authorization") == "Bearer t0k"


def test_strip_auth_off_api__redirect_to_http_api_host__drops_authorization():
    new = _redirect(github_auth.StripAuthOffApi(), "http://api.github.com/repositories/1")

    assert not new.has_header("Authorization")


def test_auth_headers__token_set_and_api_url__returns_bearer_header():
    headers = github_auth.auth_headers("https://api.github.com/repos/x/y", {"GITHUB_TOKEN": "t0k"})

    assert headers == {"Authorization": "Bearer t0k"}


def test_auth_headers__api_url_without_token__returns_nothing():
    assert github_auth.auth_headers("https://api.github.com/repos/x", {}) == {}


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/jeneric/STIG-MCP/releases/download/x",
        "https://release-assets.githubusercontent.com/x",
        "https://raw.githubusercontent.com/x",
        "http://api.github.com/repos/x",
        "https://api.github.com.evil.example/repos/x",
        "https://evil.example/api.github.com",
    ],
)
def test_auth_headers__non_api_hosts__return_nothing(url):
    assert github_auth.auth_headers(url, {"GITHUB_TOKEN": "t0k"}) == {}


@pytest.mark.parametrize("environ", [{}, {"GITHUB_TOKEN": ""}, {"GITHUB_TOKEN": " \n"}])
def test_token__unset_empty_or_whitespace__is_none(environ):
    assert github_auth.token(environ) is None


def test_token__trailing_newline__is_stripped():
    assert github_auth.token({"GITHUB_TOKEN": "t0k\n"}) == "t0k"


def test_token__environ_omitted__reads_the_process_environment(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")

    assert github_auth.token() == "from-env"


def test_rate_limited__403_with_remaining_zero__is_true():
    assert github_auth.rate_limited(_http_error(403, {"X-RateLimit-Remaining": "0"}))


def test_rate_limited__429_with_remaining_zero__is_true():
    assert github_auth.rate_limited(_http_error(429, {"X-RateLimit-Remaining": "0"}))


def test_rate_limited__403_without_the_header__is_false():
    assert not github_auth.rate_limited(_http_error(403, {}))


def test_rate_limited__403_with_remaining_left__is_false():
    assert not github_auth.rate_limited(_http_error(403, {"X-RateLimit-Remaining": "7"}))


def test_rate_limited__500__is_false():
    assert not github_auth.rate_limited(_http_error(500, {"X-RateLimit-Remaining": "0"}))


def test_rate_limit_hint__always__names_the_token_limit_and_docs_section():
    hint = github_auth.RATE_LIMIT_HINT

    assert "GITHUB_TOKEN" in hint
    assert "5,000 per hour" in hint
    assert "fine-grained" in hint
    assert "docs/install.md" in hint
    assert "GitHub's rate limit" in hint


def test_reset_time__gmtime_rejects_a_value_this_platform_cannot_hold__is_unknown(monkeypatch):
    # A 10-digit value never overflows gmtime on Linux; simulate a platform (e.g. Windows) whose
    # time_t range is narrower, since reset_time's except clause exists for exactly that case.
    def raising_gmtime(value):
        raise OverflowError("timestamp out of range for platform time_t")

    monkeypatch.setattr(github_auth.time, "gmtime", raising_gmtime)
    assert github_auth.reset_time("9999999999") is None


def test_reset_time__millisecond_value__is_unknown_not_a_wrong_far_future_date():
    # 13 ASCII digits parse and gmtime accepts them without raising, but as a reset time this is
    # milliseconds, not GitHub's seconds, and would silently print a date around the year 58710
    # if the length check did not reject it first.
    assert github_auth.reset_time("1790559566000") is None
