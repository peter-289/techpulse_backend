"""The public HTTP surface, pinned.

Every phase of this refactor has the same contract: no route is added, removed,
renamed, or given a different method or success status. That has been re-checked
by hand at the end of each phase, which is exactly the kind of check that gets
skipped once, so it is a test now.

What is asserted is the routing table only -- method, path, and the declared
success status. It cannot catch a change to a request schema, a response body, or
a handler's behaviour; those are covered by the per-context tests. It is here
because a refactor that quietly moves a route between contexts is otherwise
invisible: the code moves, the tests keep passing, and only a client notices.
"""

from __future__ import annotations

import pytest

# method, path, declared success status
# Sorted. ``HEAD``/``OPTIONS`` are dropped because Starlette adds them itself.
EXPECTED_ROUTES: list[tuple[str, str, str]] = [
    ('DELETE', '/api/v1/categories/{category_id}', '204'),
    ('DELETE', '/api/v1/resources/{slug}', '204'),
    ('GET', '/', '200'),
    ('GET', '/api/v1/admin/alerts', '200'),
    ('GET', '/api/v1/admin/audit-events', '200'),
    ('GET', '/api/v1/admin/cookie-activity', '200'),
    ('GET', '/api/v1/admin/logs', '200'),
    ('GET', '/api/v1/auth/password-reset/page', '200'),
    ('GET', '/api/v1/auth/verify', '200'),
    ('GET', '/api/v1/auth/verify-page', '200'),
    ('GET', '/api/v1/categories', '200'),
    ('GET', '/api/v1/categories/{category_id}', '200'),
    ('GET', '/api/v1/resources', '200'),
    ('GET', '/api/v1/resources/{slug}', '200'),
    ('GET', '/api/v1/software-management', '200'),
    ('GET', '/api/v1/software-management/admin/packages', '200'),
    ('GET', '/api/v1/software-management/admin/summary', '200'),
    ('GET', '/api/v1/software-management/search', '200'),
    ('GET', '/api/v1/software-management/storage/download/{storage_key:path}', '200'),
    ('GET', '/api/v1/software-management/{software_id}/versions', '200'),
    ('GET', '/api/v1/software-management/{software_id}/versions/{version}/artifacts', '200'),
    ('GET', '/api/v1/software-management/{software_id}/versions/{version}/artifacts/{artifact_id}/download', '200'),
    ('GET', '/api/v1/software-management/{software_id}/versions/{version}/download', '200'),
    ('GET', '/api/v1/support-chat/messages', '200'),
    ('GET', '/api/v1/users', '200'),
    ('GET', '/api/v1/users/me', '200'),
    ('GET', '/api/v1/users/{user_id}', '200'),
    ('GET', '/health', '200'),
    ('PATCH', '/api/v1/admin/alerts/{alert_id}/ack', '200'),
    ('PATCH', '/api/v1/categories/{category_id}', '200'),
    ('PATCH', '/api/v1/software-management/{software_id}/pricing', '200'),
    ('POST', '/api/v1/analytics/events', '202'),
    ('POST', '/api/v1/auth/login', '200'),
    ('POST', '/api/v1/auth/logout', '204'),
    ('POST', '/api/v1/auth/password-reset/confirm', '200'),
    ('POST', '/api/v1/auth/password-reset/requests', '200'),
    ('POST', '/api/v1/auth/refresh', '200'),
    ('POST', '/api/v1/categories', '201'),
    ('POST', '/api/v1/categories/{category_id}/restore', '200'),
    ('POST', '/api/v1/resources', '201'),
    ('POST', '/api/v1/software-management/upload', '201'),
    ('POST', '/api/v1/software-management/{software_id}/versions/upload', '201'),
    ('POST', '/api/v1/software-management/{software_id}/versions/{version}/deprecate', '202'),
    ('POST', '/api/v1/software-management/{software_id}/versions/{version}/revoke', '202'),
    ('POST', '/api/v1/support-chat/messages', '201'),
    ('POST', '/api/v1/users', '201'),
]


#: Routes Fastware adds for itself. Not part of the contract, but pinned so that
#: turning the docs off is a deliberate change rather than a side effect.
DOCS_ROUTES = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}


def _all_routes() -> list[tuple[str, str, str]]:
    from app.main import app

    rows: list[tuple[str, str, str]] = []
    for route in app.routes:
        methods = getattr(route, "methods", None)
        if not methods:
            continue  # a Mount or WebSocket, not part of the HTTP surface
        for method in sorted(methods - {"HEAD", "OPTIONS"}):
            rows.append((method, route.path, str(getattr(route, "status_code", None) or 200)))
    return sorted(rows)


@pytest.fixture(scope="module")
def all_routes() -> list[tuple[str, str, str]]:
    return _all_routes()


@pytest.fixture(scope="module")
def api_routes(all_routes) -> list[tuple[str, str, str]]:
    return [row for row in all_routes if row[1] not in DOCS_ROUTES]


def test_route_count_is_unchanged(api_routes) -> None:
    assert len(api_routes) == len(EXPECTED_ROUTES)


def test_route_table_is_unchanged(api_routes) -> None:
    expected = sorted(EXPECTED_ROUTES)
    added = [row for row in api_routes if row not in expected]
    removed = [row for row in expected if row not in api_routes]
    assert not added and not removed, (
        f"the public HTTP surface changed\n  added: {added}\n  removed: {removed}"
    )


def test_the_only_non_api_routes_are_the_docs_ones(all_routes) -> None:
    unexpected = [row for row in all_routes if row[1] not in DOCS_ROUTES and row not in EXPECTED_ROUTES]
    assert unexpected == []
