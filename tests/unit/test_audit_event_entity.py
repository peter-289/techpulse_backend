"""The AuditEvent entity's validity rules.

The entity is new in Phase 4. What it adds over the ORM row it replaces is a
statement about what a well-formed audit record is -- previously the service
built a row from whatever it was handed and let the database decide.

The path truncation test is the regression that matters. The service used to
truncate ``path`` to 500 characters while the column is ``varchar(255)``: a
request with a path between those lengths raised a database error and lost the
audit event entirely. Truncating at a fixed length is a storage decision, so it
belongs to the mapper, and the domain keeps the path whole.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.modules.security.domain.entities.audit_event import AuditEvent
from app.modules.security.domain.exceptions import AuditEventInvalidError
from app.modules.security.infrastructure.persistence.mappers.audit_mapper import event_to_model


def _event(**overrides) -> AuditEvent:
    kwargs = {
        "event_type": "http.request",
        "method": "get",
        "path": "/api/v1/software",
        "status_code": 200,
        "ip_address": "203.0.113.9",
    }
    kwargs.update(overrides)
    return AuditEvent.create(**kwargs)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"event_type": ""}, "type is required"),
        ({"path": ""}, "path is required"),
        ({"path": "   "}, "path is required"),
        ({"method": ""}, "method is required"),
        ({"status_code": 0}, "status code out of range"),
        ({"status_code": 999}, "status code out of range"),
    ],
)
def test_a_record_that_cannot_describe_a_request_is_rejected(kwargs, message) -> None:
    """A blank type or path is a bug in the caller, not a fact worth keeping.

    Storing it anyway makes the trail useless for the investigation it exists to
    support: an operator filtering on ``auth.login.failed`` has to trust that
    every row under that type is one.
    """
    with pytest.raises(AuditEventInvalidError, match=message):
        _event(**kwargs)


def test_the_method_is_normalised() -> None:
    assert _event(method=" post ").method == "POST"


def test_a_long_path_is_truncated_to_the_column_width() -> None:
    long_path = "/api/v1/software/" + "a" * 400

    event = _event(path=long_path)
    model = event_to_model(event)

    assert event.path == long_path, "the domain keeps the path whole"
    assert len(model.path) == 255, "the mapper owns the storage width"


def test_absent_optional_values_stay_absent() -> None:
    """Truncating ``None`` would store the string "None"."""
    event = _event(ip_address=None, user_agent=None)

    model = event_to_model(event)

    assert model.ip_address is None
    assert model.user_agent is None


def test_a_long_user_agent_is_truncated_without_touching_the_domain() -> None:
    agent = "x" * 500

    event = _event(user_agent=agent)

    assert event.user_agent == agent
    assert len(event_to_model(event).user_agent) == 255


def test_metadata_defaults_to_an_empty_dict() -> None:
    """The column is nullable but every reader treats it as a mapping."""
    assert _event().metadata == {}


def test_naive_timestamps_are_read_as_utc() -> None:
    event = AuditEvent.create(
        event_type="http.request",
        method="get",
        path="/api/v1/software",
        status_code=200,
        occurred_at=datetime(2026, 1, 2, 3, 4, 5),
    )

    assert event.occurred_at == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def test_an_unpersisted_event_has_no_id() -> None:
    """The id is an autoincrement, so it is only known after the insert."""
    assert _event().id is None
