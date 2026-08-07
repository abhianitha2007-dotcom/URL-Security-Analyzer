import pytest

from analyzer import safe_http
from analyzer.safe_http import (
    SafeRequests,
    UnsafeTargetError
)
from analyzer.url_validator import is_valid_url


# =========================================================
# URL VALIDATOR TESTS
# =========================================================

@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1",
        "http://localhost",
        "http://localhost:5000",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://169.254.169.254",
        "http://[::1]",
        "ftp://example.com",
        "file:///etc/passwd",
        "http://user:password@example.com",
    ],
)
def test_url_validator_blocks_unsafe_targets(url):
    assert is_valid_url(url) is False


def test_url_validator_allows_global_ip():
    assert is_valid_url("https://8.8.8.8") is True


# =========================================================
# SAFE HTTP TEST DOUBLES
# =========================================================

class FakeResponse:

    def __init__(
        self,
        status_code,
        url,
        headers=None
    ):
        self.status_code = status_code
        self.url = url
        self.headers = headers or {}
        self.history = []


class FakeSession:

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.trust_env = True
        self.closed = False

    def request(
        self,
        method,
        url,
        **kwargs
    ):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "kwargs": kwargs,
            }
        )

        if not self.responses:
            raise AssertionError(
                "FakeSession has no response left."
            )

        return self.responses.pop(0)

    def close(self):
        self.closed = True


def install_fake_session(
    monkeypatch,
    responses
):
    fake_session = FakeSession(
        responses
    )

    monkeypatch.setattr(
        safe_http.requests,
        "Session",
        lambda: fake_session
    )

    return fake_session


# =========================================================
# SAFE HTTP REDIRECT / SSRF TESTS
# =========================================================

def test_safe_http_blocks_redirect_to_private_ip(
    monkeypatch
):
    fake_session = install_fake_session(
        monkeypatch,
        [
            FakeResponse(
                302,
                "https://public.example/start",
                {
                    "Location":
                        "http://127.0.0.1/admin"
                }
            )
        ]
    )

    monkeypatch.setattr(
        safe_http,
        "is_valid_url",
        lambda url:
            not url.startswith(
                "http://127.0.0.1"
            )
    )

    client = SafeRequests()

    with pytest.raises(
        UnsafeTargetError
    ):
        client.get(
            "https://public.example/start"
        )

    assert len(
        fake_session.calls
    ) == 1

    assert fake_session.calls[0][
        "url"
    ] == "https://public.example/start"

    assert fake_session.trust_env is False
    assert fake_session.closed is True


def test_safe_http_follows_valid_relative_redirect(
    monkeypatch
):
    fake_session = install_fake_session(
        monkeypatch,
        [
            FakeResponse(
                302,
                "https://public.example/start",
                {
                    "Location":
                        "/next"
                }
            ),
            FakeResponse(
                200,
                "https://public.example/next"
            ),
        ]
    )

    monkeypatch.setattr(
        safe_http,
        "is_valid_url",
        lambda url: (
            url.startswith(
                "https://public.example/"
            )
        )
    )

    client = SafeRequests()

    response = client.get(
        "https://public.example/start"
    )

    assert response.status_code == 200

    assert [
        call["url"]
        for call in fake_session.calls
    ] == [
        "https://public.example/start",
        "https://public.example/next",
    ]

    assert len(
        response.history
    ) == 1

    assert response.history[0].status_code == 302
    assert fake_session.closed is True


def test_safe_http_does_not_follow_redirect_when_disabled(
    monkeypatch
):
    fake_session = install_fake_session(
        monkeypatch,
        [
            FakeResponse(
                302,
                "https://public.example/start",
                {
                    "Location":
                        "https://public.example/next"
                }
            )
        ]
    )

    monkeypatch.setattr(
        safe_http,
        "is_valid_url",
        lambda url: True
    )

    client = SafeRequests()

    response = client.get(
        "https://public.example/start",
        allow_redirects=False
    )

    assert response.status_code == 302
    assert len(
        fake_session.calls
    ) == 1
    assert response.history == []
    assert fake_session.closed is True


def test_safe_http_applies_default_timeout(
    monkeypatch
):
    fake_session = install_fake_session(
        monkeypatch,
        [
            FakeResponse(
                200,
                "https://public.example/"
            )
        ]
    )

    monkeypatch.setattr(
        safe_http,
        "is_valid_url",
        lambda url: True
    )

    client = SafeRequests()

    client.get(
        "https://public.example/"
    )

    assert fake_session.calls[0][
        "kwargs"
    ]["timeout"] == safe_http.DEFAULT_TIMEOUT


def test_safe_http_rejects_initial_unsafe_target(
    monkeypatch
):
    fake_session = install_fake_session(
        monkeypatch,
        []
    )

    monkeypatch.setattr(
        safe_http,
        "is_valid_url",
        lambda url: False
    )

    client = SafeRequests()

    with pytest.raises(
        UnsafeTargetError
    ):
        client.get(
            "http://127.0.0.1"
        )

    assert fake_session.calls == []