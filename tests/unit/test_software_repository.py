"""The purchase check, which is the one port member with no query behind it.

``ISoftwareRepository.has_purchase`` is the only method on the port that
``SQLAlchemySoftwareRepository`` originally failed to implement. Because the
repository subclasses the protocol explicitly, the omission was invisible: the
inherited ``...`` body returned ``None`` for every user. ``None`` is falsy, and a
falsy ``None`` is indistinguishable from a real answer, so every purchase check
answered "this user bought nothing" without any sign that the question had gone
unasked.

That is what these tests are for, in two halves. The architectural half — that no
port member is answered by an inherited body — is
``tests/architecture/test_ports_have_no_silent_defaults.py``. This file is the
behavioural half, and it exists because the architectural guard cannot see it: the
repository now overrides the method, so nothing inherits anything, and deleting
that override outright still passes every rule. Proven, by deleting it: the
architecture suite stays green and only a request reaching the method finds out.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.infrastructure.database.db_setup import Base
from app.modules.software_management.domain.entities.software import Software
from app.modules.software_management.domain.ports.repositories.software_repository import (
    ISoftwareRepository,
)
from app.modules.software_management.infrastructure.persistence.repositories.sqlalchemy_software_repository import (  # noqa: E501
    SQLAlchemySoftwareRepository,
)


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as db:
        yield db
    await engine.dispose()


@pytest.mark.asyncio
async def test_the_repository_answers_the_purchase_question(session) -> None:
    """The repository answers, rather than leaving the question to the port.

    ``False`` is the truthful answer today: there is no purchase table, the
    ``billing`` module that owned it was removed, and so no purchase can be
    recorded. What matters is that the answer is stated at the adapter that owns
    the knowledge of that, rather than arriving by inheritance from a body nobody
    wrote.
    """
    repository = SQLAlchemySoftwareRepository(session)

    assert await repository.has_purchase(
        software_id=uuid4(), user_id=uuid4()
    ) is False, (
        "expected False: no purchase can be recorded, so nobody can be a buyer"
    )


@pytest.mark.asyncio
async def test_the_answer_is_false_for_every_user_not_just_a_sample(session) -> None:
    """Falsy is not the same as False, and a caller may test either.

    ``None`` and ``False`` are both falsy, which is precisely why the inherited
    body was able to pass for an answer. Pinning the type as well as the value
    means a future edit that returns ``None`` again fails here.
    """
    repository = SQLAlchemySoftwareRepository(session)

    for _ in range(3):
        answer = await repository.has_purchase(software_id=uuid4(), user_id=uuid4())
        assert answer is False, f"expected the bool False, got {answer!r}"


@pytest.mark.asyncio
async def test_the_port_refuses_to_default_the_answer() -> None:
    """An implementation that forgets the override must fail loudly.

    This is the property that makes the omission detectable at all. With a ``...``
    body the call succeeds and returns ``None``; here it raises, so the mistake
    surfaces at the call with the port in the traceback rather than as a quietly
    wrong authorization decision.
    """

    class _IncompleteRepository(ISoftwareRepository):
        pass

    with pytest.raises(NotImplementedError) as raised:
        await _IncompleteRepository().has_purchase(  # type: ignore[abstract]
            software_id=uuid4(), user_id=uuid4()
        )

    assert "has_purchase" in str(raised.value)
    assert "purchase" in str(raised.value).lower()


def test_the_concrete_repository_overrides_the_port() -> None:
    """The override is the whole fix, so its absence has to be a test failure.

    The architecture sweep is satisfied either way — a declared raising member is
    allowed to be inherited — so deleting this method leaves every rule green. This
    is the test that notices.
    """
    assert "has_purchase" in SQLAlchemySoftwareRepository.__dict__, (
        "SQLAlchemySoftwareRepository must state its own has_purchase answer. "
        "Without it the port's body is used, which is the defect this file records."
    )


def test_a_paid_software_is_reachable_only_by_its_owner() -> None:
    """Why the falsy answer is the correct one today, rather than a lucky one.

    A non-zero price at upload makes the product ``PURCHASE_REQUIRED``
    (``Software.create`` derives the access type from the price), and nothing can
    grant it: no endpoint calls ``change_access_policy``, and no purchase can be
    recorded. So "nobody is a buyer" is a fact about the system, not an accident,
    and the owner's short-circuit is what keeps an owner off the purchase question
    entirely.
    """
    owner_id = uuid4()
    paid = Software.create(
        name="Paid",
        description="d",
        owner_id=owner_id,
        price_cents=5_000,
    )

    assert paid.requires_payment() is True, "a priced upload must require payment"
    assert paid.is_owned_by(owner_id) is True
    assert paid.is_owned_by(uuid4()) is False
