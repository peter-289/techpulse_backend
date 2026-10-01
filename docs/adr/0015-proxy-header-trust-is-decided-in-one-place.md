# ADR 0015: Proxy-header trust is decided in one place

- **Status:** Accepted
- **Date:** 2026-10-01
- **Deciders:** backend maintainers
- **Supersedes:** nothing
- **Related:** ADR 0013 (a port member may not silently default)

## Context

Every IP-keyed control in this codebase — the login brute-force limiter, the
registration guard, the upload and download rate limits, and the audit log —
resolves the client address through one function:

```python
# app/modules/security/abuse_protection.py
def get_client_ip(self, request: Request) -> str:
    if settings.TRUST_PROXY_HEADERS:
        ... # reads X-Forwarded-For, then X-Real-IP
    return request.client.host if request.client else ""
```

Its own docstring records why the forwarded headers are gated: both are
trivially spoofable, so trusting them unconditionally lets a client mint a
fresh rate-limit bucket per request and fully defeats the brute-force limiter.
`TRUST_PROXY_HEADERS` therefore defaults to `False`.

The problem is that this is only *half* of the trust decision, and the other
half was not under this codebase's control.

`uvicorn` installs `ProxyHeadersMiddleware` **by default**
(`uvicorn.Config.proxy_headers` defaults to `True`). Before the application sees
a request, that middleware rewrites the ASGI scope's `client` from a
client-supplied `X-Forwarded-For` whenever the connecting peer is in
`FORWARDED_ALLOW_IPS`, which in turn defaults to `127.0.0.1`:

```python
# uvicorn/middleware/proxy_headers.py
if self.always_trust or client_host in self.trusted_hosts:
    ...
    scope["client"] = (host, port)
```

The `return request.client.host` line above therefore does not return the
socket peer. It returns whatever the header said. `TRUST_PROXY_HEADERS=false`
disabled only the explicit header reads and left the implicit ones untouched.

There was also a second, quieter defect. `app/main.py` constructed the app as:

```python
app = IterableFastAPI(..., proxy_headers=True)
```

FastAPI has no `proxy_headers` parameter. It falls into `**extra` and is
**silently discarded** — `Starlette.__init__` accepts only `debug`, `routes`,
`middleware`, `exception_handlers`, `on_startup`, `on_shutdown` and `lifespan`,
so the attribute never lands anywhere. That line read as a deliberate,
security-relevant decision while configuring nothing. It is the same failure
mode as ADR 0013: an argument that looks like it enforces something and
enforces nothing.

## Decision

**One setting decides proxy trust, and it is enforced at both layers.**

`docker-entrypoint.sh` derives uvicorn's flag from the same
`TRUST_PROXY_HEADERS` value the application reads:

| `TRUST_PROXY_HEADERS` | uvicorn flags |
|---|---|
| unset / `false` / `0` / `no` | `--no-proxy-headers` |
| `true` / `1` / `yes` / `on` | `--proxy-headers --forwarded-allow-ips=$FORWARDED_ALLOW_IPS` (default `127.0.0.1`) |

`FORWARDED_ALLOW_IPS=*` is refused at start-up with a non-zero exit rather
than honoured, because it trusts a client-supplied `X-Forwarded-For` from any
peer and reinstates exactly the bypass this setting exists to prevent.

`app/main.py` no longer passes `proxy_headers`. The absence is commented at the
call site, and `tests/unit/test_entrypoint_proxy_trust.py` asserts both that
the kwarg has not returned and that each value of `TRUST_PROXY_HEADERS`
produces the intended uvicorn flags.

## Rationale

The alternative was to leave the application half alone and document that
operators must set `FORWARDED_ALLOW_IPS` themselves. Rejected: two switches for
one decision is how `TRUST_PROXY_HEADERS=true` and `FORWARDED_ALLOW_IPS` drift
apart, and the failure mode is silent in both directions. Setting only the
former means the app trusts headers that uvicorn never substituted; setting
only the latter, or setting it to `*`, bypasses the limiter while the
application still reports itself as not trusting proxies.

Passing `--no-proxy-headers` unconditionally was also rejected. It would be
correct for a directly-exposed deployment and wrong for the common one behind
nginx, and it would push the decision onto an env var the codebase does not own.

Refusing `*` rather than merely defaulting away from it is deliberate. The
value is a well-intentioned attempt to "make proxy headers work" that
reintroduces the bypass, and the failure is invisible until someone brute-forces
a login.

## Consequences

**Good**

- `TRUST_PROXY_HEADERS=false` now genuinely means proxy headers are untrusted.
- One documented switch, with the reasoning in one file.
- A misleading no-op argument is gone from the application factory.

**Bad**

- `FORWARDED_ALLOW_IPS` no longer defaults from the environment when
  `TRUST_PROXY_HEADERS` is false. That is the point, but an operator who set it
  globally will see it ignored.
- Refusing `*` turns a working deployment into a failed start. The error names
  the variable and the alternative, but it is still a hard failure.

**Neutral**

- With `--no-proxy-headers`, `X-Forwarded-Proto` is no longer honoured either,
  so `request.url.scheme` no longer reflects the proxy's view. Nothing in this
  codebase reads it — no `url_for`, no scheme check, no HTTPS detection — so
  there is no behaviour change today. Anything added later that inspects the
  scheme must account for this.
- `get_client_ip` reads `X-Forwarded-For.split(",")[0]`, the *first* hop, which
  is the client-controlled end. That is correct only under the precondition
  already documented at the call site: the proxy strips inbound forwarding
  headers. It stays as it is; this ADR changes who decides, not what is read.