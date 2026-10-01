#!/bin/sh
set -e

# This script starts the web server and nothing else.
#
# Schema changes deliberately do NOT run here. They used to, on every
# container start, which coupled a deploy to a migration: every replica
# re-ran `alembic upgrade head`, a rollback or a restart could apply a
# migration nobody asked for, and a failing migration took the web process
# down with it instead of stopping the deploy cleanly.
#
# Migrations now run as their own one-shot step -- the `migrate` service in
# docker-compose.yml, which `api` waits on via
# `condition: service_completed_successfully`. One process, runs to
# completion, exits non-zero on failure and the deploy stops there.

# Proxy-header trust is decided here, and only here.
#
# uvicorn enables ProxyHeadersMiddleware by default (uvicorn Config
# proxy_headers=True), and it rewrites scope["client"] from a client-supplied
# X-Forwarded-For whenever the connecting peer is in FORWARDED_ALLOW_IPS,
# which itself defaults to 127.0.0.1. Everything keyed on the client IP --
# the login brute-force limiter, registration and upload guards, and the audit
# log -- reads request.client.host, so wherever the peer is trusted, a client
# can mint a fresh rate-limit bucket per request by rotating the header.
#
# TRUST_PROXY_HEADERS is the same decision from the application side
# (abuse_protection.get_client_ip). Deriving the uvicorn flag from it keeps
# the two halves from disagreeing: setting it to false actually disables proxy
# trust now, instead of only disabling half of it.
PROXY_ARGS="--no-proxy-headers"

case "$(printf '%s' "${TRUST_PROXY_HEADERS:-false}" | tr '[:upper:]' '[:lower:]')" in
    true|1|yes|on)
        # Only trust forwarded headers from an address that is actually the
        # proxy. "*" is refused rather than honoured: it trusts a
        # client-supplied X-Forwarded-For from any peer, which defeats every
        # IP rate limit including the brute-force limiter.
        ALLOWED_PROXY_IPS="${FORWARDED_ALLOW_IPS:-127.0.0.1}"
        if [ "$ALLOWED_PROXY_IPS" = "*" ]; then
            echo "Refusing FORWARDED_ALLOW_IPS='*'." >&2
            echo "That trusts a client-supplied X-Forwarded-For from any peer," >&2
            echo "which defeats every IP rate limit. Set it to the proxy's" >&2
            echo "address instead, or unset TRUST_PROXY_HEADERS." >&2
            exit 1
        fi
        PROXY_ARGS="--proxy-headers --forwarded-allow-ips=$ALLOWED_PROXY_IPS"
        ;;
esac

echo "Starting TechPulse API..."

exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port ${PORT:-8000} \
    $PROXY_ARGS