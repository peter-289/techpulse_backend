from app.core.config import AppSettings, settings
from app.modules.security.abuse_protection import LOGIN_POLICY


def test_login_policy_matches_runtime_settings() -> None:
    assert LOGIN_POLICY.capacity == settings.AUTH_LOGIN_RATE_LIMIT
    assert LOGIN_POLICY.refill_rate == settings.AUTH_LOGIN_RATE_LIMIT / settings.AUTH_LOGIN_WINDOW_SECONDS


def test_local_http_cookie_settings_are_normalized() -> None:
    config = AppSettings(
        BACKEND_URL="http://localhost:8000",
        FRONTEND_URL="http://localhost:5173/",
        COOKIE_DOMAIN="COOKIE_DOMAIN",
        COOKIE_SECURE=True,
        COOKIE_SAMESITE="none",
    )

    assert config.COOKIE_DOMAIN is None
    assert config.COOKIE_SECURE is False
    assert config.COOKIE_SAMESITE == "lax"
