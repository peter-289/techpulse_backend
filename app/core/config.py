from pathlib import Path
from urllib.parse import quote, urlparse


from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = Path(__file__).resolve().parents[2]

_VALID_ENVIRONMENTS = {"development", "staging", "production", "test"}

#: Passwords that appear in templates, tutorials and breach lists. Refused for
#: the seeded superuser, where the value is the only thing standing between an
#: unauthenticated caller and the admin API.
_PLACEHOLDER_PASSWORDS = {
    "change_me", "changeme", "changeit", "password", "admin",
    "secret", "replace_me", "replaceme", "placeholder", "todo",
    "admin123", "password123", "letmein",
}

_MIN_SUPERUSER_PASSWORD_LENGTH = 12

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _split_origins(raw: str) -> list[str]:
    """Split a comma-separated origin list the way main.py normalises it."""
    origins: list[str] = []
    for item in (raw or "").split(","):
        clean = item.strip().rstrip("/")
        if clean and clean not in origins:
            origins.append(clean)
    return origins

def _normalize_smtp_host(value: str) -> str:
    host = (value or "").strip()
    if not host:
        return host
    parsed = urlparse(host)
    if parsed.scheme:
        return parsed.hostname or host
    return host


def _resolve_path(value: str, fallback: str) -> str:
    raw = (value or "").strip() or fallback
    path = Path(raw)
    if not path.is_absolute():
        path = (BACKEND_ROOT / path).resolve()
    return str(path)


def _normalize_database_url(value: str) -> str:
    raw = (value or "").strip()
    if not raw.startswith("sqlite:///"):
        return raw

    sqlite_path = raw[len("sqlite:///") :]
    if not sqlite_path or sqlite_path == ":memory:":
        return raw

    candidate = Path(sqlite_path)
    if not candidate.is_absolute():
        candidate = (BACKEND_ROOT / candidate).resolve()

    return f"sqlite:///{candidate.as_posix()}"


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(PROJECT_ROOT / ".env", BACKEND_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    
    # Core
    DATABASE_URL_ASYNC: str = ""
    DATABASE_URL_SYNC: str = ""
    SECRET_KEY: str = ""
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 1800
    
    # Logging/Audit
    LOG_LEVEL: str = "INFO"
    LOG_DIR: str = "logs"
    LOG_FILE_PATH: str = ""
    LOG_MAX_BYTES: int = 10 * 1024 * 1024
    LOG_BACKUP_COUNT: int = 5
    AUDIT_ENABLED: bool = True
    ALERT_LOGIN_FAILURE_THRESHOLD: int = 5
    ALERT_ACCESS_DENIED_THRESHOLD: int = 10
    ALERT_LOOKBACK_MINUTES: int = 15
    ALERT_DEDUP_MINUTES: int = 15

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str | None = None
    REDIS_DB: int = 0
    REDIS_USERNAME: str | None = None

    # Reverse proxy
    # X-Forwarded-For / X-Real-IP are attacker-controlled unless a trusted proxy
    # overwrites them. Only enable this when a proxy you control sits in front of
    # the app AND strips these headers from inbound client requests; otherwise the
    # client can spoof a fresh IP per request to bypass every IP rate limit
    # (including the login brute-force limiter).
    # This is the single switch: docker-entrypoint.sh derives uvicorn's
    # --proxy-headers flag from it, so the server and application layers cannot
    # disagree. See docs/adr/0015-proxy-header-trust-is-decided-in-one-place.md.
    TRUST_PROXY_HEADERS: bool = False

    # Deployment
    ENVIRONMENT: str = "development"
    SERVE_API_DOCS: bool | None = None


    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


    @property
    def api_docs_enabled(self) -> bool:
        """Whether /docs, /redoc and /openapi.json are served.

        Off in production so the full route surface is not published. An
        explicit SERVE_API_DOCS overrides the environment either way, which is
        what lets the surface test pin those routes without depending on it.
        """
        if self.SERVE_API_DOCS is not None:
            return self.SERVE_API_DOCS
        return not self.is_production


    @property
    def REDIS_URL(self) -> str:
        host = (self.REDIS_HOST or "localhost").strip()
        if host.startswith(("redis://", "rediss://")):
            return host

        auth = ""
        username = (self.REDIS_USERNAME or "").strip()
        password = (self.REDIS_PASSWORD or "").strip()

        if username and password:
            auth = f"{quote(username)}:{quote(password)}@"
        elif username:
            auth = f"{quote(username)}@"
        elif password:
            auth = f":{quote(password)}@"

        return f"redis://{auth}{host}:{self.REDIS_PORT}/{self.REDIS_DB}"


    # Email
    EMAIL_FROM: str = "no-reply@techpulse.local"
    EMAIL_SUBJECT: str = "Welcome to Tech Pulse"
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 1025
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_USE_TLS: bool = False
    SMTP_USE_SSL: bool = False
    SMTP_VALIDATE_CERTS: bool =False

    # URLs
    BASE_URL: str = "http://127.0.0.1:8000"
    FRONTEND_URL: str = "http://localhost:5173/"
    BACKEND_URL: str = ""

    # Project management
    UPLOAD_ROOT: str = "storage"
    PACKAGE_STORAGE_BACKEND: str = "local"
    PACKAGE_UPLOAD_MAX_SIZE_BYTES: int = 5 * 1024 * 1024 * 1024
    PACKAGE_UPLOAD_CHUNK_SIZE_BYTES: int = 1024 * 1024
    PACKAGE_USER_QUOTA_BYTES: int = 25 * 1024 * 1024 * 1024
    PACKAGE_UPLOAD_RATE_LIMIT: int = 30
    PACKAGE_UPLOAD_RATE_WINDOW_SECONDS: int = 60
    PACKAGE_DOWNLOAD_RATE_LIMIT: int = 120
    PACKAGE_DOWNLOAD_RATE_WINDOW_SECONDS: int = 60
    # The signed-artifact serving path is not configurable. It was, via
    # STORAGE_DOWNLOAD_PATH, which defaulted to "" and so produced signed URLs of
    # the shape http://host//software/... -- a target no route matched. The route
    # itself is declared in software_router; keeping the two in one place means
    # one constant, SIGNED_DOWNLOAD_ROUTE, instead of an env var that has to be
    # kept in step with the decorator by hand.
    URL_EXPIRY_MAX_SECONDS: int = 900

    # Payments
    PAYMENT_PROVIDER: str = "manual"
    PAYMENT_PROVIDER_PUBLIC_KEY: str = ""
    PAYMENT_PROVIDER_SECRET_KEY: str = ""
    PAYMENT_WEBHOOK_SECRET: str = ""

    # Malware scanning
    MALWARE_SCAN_PROVIDER: str = "local"
    MALWARE_SCAN_API_URL: str = ""
    MALWARE_SCAN_API_KEY: str = ""

    # Authentication
    ALGORITHM: str = "HS256"
    LOGIN_TOKEN_EXPIRE_MINUTES: int = 30
    EMAIL_TOKEN_EXPIRE_MINUTES: int = 60
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 30
    EMAIL_VERIFY_SECRET: str = ""
    PASSWORD_RESET_SECRET: str = ""
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14
    REFRESH_REQUIRE_SAME_USER_AGENT: bool = True
    REFRESH_REQUIRE_SAME_IP: bool = False

    # Auth abuse protection
    AUTH_LOGIN_RATE_LIMIT: int = 10
    AUTH_LOGIN_WINDOW_SECONDS: int = 60
    AUTH_REFRESH_RATE_LIMIT: int = 30
    AUTH_REFRESH_WINDOW_SECONDS: int = 60
    AUTH_PASSWORD_RESET_REQUEST_RATE_LIMIT: int = 5
    AUTH_PASSWORD_RESET_REQUEST_WINDOW_SECONDS: int = 300
    AUTH_PASSWORD_RESET_CONFIRM_RATE_LIMIT: int = 10
    AUTH_PASSWORD_RESET_CONFIRM_WINDOW_SECONDS: int = 300

    # Compatibility
    EXPOSE_ACCESS_TOKEN_IN_BODY: bool = False

    # AI
    AI_API_KEY: str = ""
    AI_BASE_URL: str = "https://api.openai.com/v1"
    WHISPER_MODEL: str = "whisper-1"
    SUPPORT_CHAT_MODEL: str = "gpt-4o-mini"
    TRANSCRIPTION_BASE_URL: str = ""

    # Startup superuser seeding
    #
    # There is deliberately no STARTUP_RUN_MIGRATIONS here. Schema changes run
    # as their own one-shot step (the `migrate` service in docker-compose.yml),
    # not from the application lifecycle, so that a restart or a rolling deploy
    # can never run a migration as a side effect of starting a web worker.
    SUPERUSER_SEED_ENABLED: bool = True
    SUPERUSER_FULL_NAME: str = ""
    SUPERUSER_USERNAME: str = ""
    SUPERUSER_EMAIL: str = ""
    SUPERUSER_PASSWORD: str = ""
    SUPERUSER_UPDATE_PASSWORD_ON_STARTUP: bool = False
    
    # Session cookies
    ACCESS_COOKIE_NAME: str = "tp_access"
    REFRESH_COOKIE_NAME: str = "tp_refresh"
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: str = "lax"
    COOKIE_DOMAIN: str | None = None
    ACCESS_COOKIE_PATH: str = "/"
    REFRESH_COOKIE_PATH: str = "/api/v1/auth"

    # Email retry
    EMAIL_RETRY_MAX_ATTEMPTS: int = 4
    EMAIL_RETRY_BASE_DELAY_SECONDS: int = 2
    EMAIL_RETRY_MAX_DELAY_SECONDS: int = 30

    # Email verification recovery loop
    EMAIL_RECOVERY_ENABLED: bool = True
    EMAIL_RECOVERY_INTERVAL_SECONDS: int = 120
    EMAIL_RECOVERY_ELIGIBLE_AGE_SECONDS: int = 120
    EMAIL_RECOVERY_MAX_BATCH_SIZE: int = 100
    EMAIL_RECOVERY_MAX_RETRY_COUNT: int = 20
    EMAIL_RECOVERY_BACKOFF_BASE_SECONDS: int = 120
    EMAIL_RECOVERY_BACKOFF_MAX_SECONDS: int = 3600
    EMAIL_RECOVERY_STARTUP_DELAY_SECONDS: int = 15

    @model_validator(mode="after")
    def normalize_and_validate(self) -> "AppSettings":
        self.ENVIRONMENT = (self.ENVIRONMENT or "development").strip().lower()
        if self.ENVIRONMENT not in _VALID_ENVIRONMENTS:
            raise RuntimeError(
                f"ENVIRONMENT must be one of {sorted(_VALID_ENVIRONMENTS)}."
            )

        # Database URLs
        self.DATABASE_URL_ASYNC= _normalize_database_url(self.DATABASE_URL_ASYNC)
        self.DATABASE_URL_SYNC = _normalize_database_url(self.DATABASE_URL_SYNC)

        # Log management
        self.LOG_LEVEL = (self.LOG_LEVEL or "INFO").upper()
        self.LOG_DIR = _resolve_path(self.LOG_DIR, "logs")
        self.LOG_FILE_PATH = _resolve_path(self.LOG_FILE_PATH, str(Path(self.LOG_DIR) / "app.log"))
        
        # Backend URL/ upload root & package storage backend
        self.BACKEND_URL = (self.BACKEND_URL or self.BASE_URL or "http://127.0.0.1:8000").strip()
        self.UPLOAD_ROOT = _resolve_path(self.UPLOAD_ROOT, "storage")
        self.PACKAGE_STORAGE_BACKEND = (self.PACKAGE_STORAGE_BACKEND or "local").lower()

        # Payment provider
        self.PAYMENT_PROVIDER = (self.PAYMENT_PROVIDER or "manual").lower()
        
        # Mail management
        self.SMTP_HOST = _normalize_smtp_host(self.SMTP_HOST)

        # Malware scan provider
        self.MALWARE_SCAN_PROVIDER = (self.MALWARE_SCAN_PROVIDER or "local").lower()

        # Cookie management
        self.COOKIE_SAMESITE = (self.COOKIE_SAMESITE or "lax").lower()
        cookie_domain = (self.COOKIE_DOMAIN or "").strip()
        if cookie_domain.upper() in {"COOKIE_DOMAIN", "NONE", "NULL", ""}:
            cookie_domain = ""
        self.COOKIE_DOMAIN = cookie_domain or None

        is_local_http = (
            (self.BACKEND_URL or "").lower().startswith("http://")
            or (self.FRONTEND_URL or "").lower().startswith("http://")
        )
        if is_local_http:
            self.COOKIE_SECURE = False
        if self.COOKIE_SAMESITE == "none" and not self.COOKIE_SECURE:
            self.COOKIE_SAMESITE = "lax"

        # Password reset secret
        self.PASSWORD_RESET_SECRET = (
            (self.PASSWORD_RESET_SECRET or "").strip()
            or self.EMAIL_VERIFY_SECRET
            or self.SECRET_KEY
        )

        if self.PACKAGE_STORAGE_BACKEND not in {"local", "object"}:
            raise RuntimeError("PACKAGE_STORAGE_BACKEND must be 'local' or 'object'.")
        if self.PAYMENT_PROVIDER not in {"manual"}:
            raise RuntimeError("PAYMENT_PROVIDER must be 'manual' until a provider adapter is configured.")
        if self.MALWARE_SCAN_PROVIDER not in {"local"}:
            raise RuntimeError("MALWARE_SCAN_PROVIDER must be 'local' until a scanner adapter is configured.")
        if self.COOKIE_SAMESITE not in {"lax", "strict", "none"}:
            raise RuntimeError("COOKIE_SAMESITE must be one of: lax, strict, none.")
        if self.COOKIE_SAMESITE == "none" and not self.COOKIE_SECURE:
            raise RuntimeError("COOKIE_SAMESITE='none' requires COOKIE_SECURE=True.")
        return self

    def validate_security(self) -> None:
        _assert_min_secret("SECRET_KEY", self.SECRET_KEY or "")
        _assert_min_secret("EMAIL_VERIFY_SECRET", self.EMAIL_VERIFY_SECRET or "")
        _assert_min_secret("PASSWORD_RESET_SECRET", self.PASSWORD_RESET_SECRET or "")
        self._validate_superuser_credentials()
        self._validate_production_cors()


    def _validate_production_cors(self) -> None:
        """A production deployment must name a real frontend origin.

        FRONTEND_URL defaults to a loopback address, and it seeds an
        ``allow_credentials=True`` CORS allowlist. Left at the default in
        production, any page a developer happens to have open on their own
        machine could make authenticated cross-origin calls. A browser only
        ever sends the origin the user actually navigated to, so a real
        deployment can always name its real frontend here.
        """
        if not self.is_production:
            return

        for origin in _split_origins(self.FRONTEND_URL):
            host = (urlparse(origin).hostname or "").strip().lower()
            if host in _LOOPBACK_HOSTS:
                raise RuntimeError(
                    f"FRONTEND_URL is {origin!r}, a loopback origin, while "
                    f"ENVIRONMENT=production. CORS is credentialed, so this "
                    f"would let any page on a developer's machine make "
                    f"authenticated calls. Set FRONTEND_URL to the public "
                    f"frontend origin."
                )


    def _validate_superuser_credentials(self) -> None:
        """Refuse to seed an admin from a template or trivially weak password.

        Checked at start-up rather than at import so a stray value cannot take
        the whole test collection down, but before anything is seeded. A
        seeded superuser is an unauthenticated path to full administrative
        access, and ``.env.example`` used to ship a working pair
        (``SUPERUSER_SEED_ENABLED=true`` with ``SUPERUSER_PASSWORD=change_me``)
        that nothing rejected.
        """
        if not self.SUPERUSER_SEED_ENABLED:
            return

        password = (self.SUPERUSER_PASSWORD or "").strip()
        if not password:
            # seed_superuser skips and warns; not an error.
            return

        if password.lower() in _PLACEHOLDER_PASSWORDS:
            raise RuntimeError(
                "SUPERUSER_PASSWORD is a placeholder value. It would seed an "
                "administrator account reachable with a password published in "
                "the template. Set a real one, or set SUPERUSER_SEED_ENABLED=false."
            )
        if len(password) < _MIN_SUPERUSER_PASSWORD_LENGTH:
            raise RuntimeError(
                f"SUPERUSER_PASSWORD must be at least "
                f"{_MIN_SUPERUSER_PASSWORD_LENGTH} characters when "
                f"SUPERUSER_SEED_ENABLED is true."
            )


settings = AppSettings()

def _assert_min_secret(name: str, value: str, min_len: int = 32) -> None:
    if not value or len(value.strip()) < min_len:
        raise RuntimeError(f"{name} must be set and at least {min_len} characters long.")
