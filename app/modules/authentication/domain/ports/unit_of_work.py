"""The authentication context's Unit of Work port.

Authentication *authorises*; it does not *own* the User concept. So this port
does not expose ``user_repo`` at all. ``AuthService`` needs to read a user by
username and by id, and to write sessions, so it borrows the user context's
repositories through this port.

Why the borrowing is declared here rather than the user context depending on
authentication: the dependency has to point the way that keeps the context that
defines the concept in charge of how it is exposed. ``user`` decides what a
``UserRepository`` can do; ``authentication`` decides it needs that capability.
The port is a capability grant, and writing it in the consumer is what keeps
the provider from accumulating a god-interface for every consumer.

See ``app/modules/shared/unit_of_work.py`` and ``docs/adr/0001``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.modules.shared.unit_of_work import UnitOfWorkPort


@runtime_checkable
class AuthenticationUnitOfWork(UnitOfWorkPort, Protocol):
    """Transaction boundary for the authentication context.

    Exposes exactly the capabilities ``AuthService`` uses: look up a user by id,
    username or email, and manage sessions. Anything beyond that is not
    authorisation's business and should be added to the user context's own
    services instead.
    """

    @property
    def user_repo(self) -> object:
        """User capability, borrowed from the user context.

        The returned value is a ``User`` entity, not an ORM row, since Phase 6b.

        Still ``object``, and the reason is R2 rather than an oversight: a
        bounded context may not import another context's ``domain`` at all, not
        even its ports. Only the shared adapter layer and the composition root
        are port readers. Narrowing this annotation would mean importing
        ``app.modules.user.domain.ports.repository.user_repository``, which the
        boundary checker rejects -- and it is a hard rule, so it cannot be
        ratcheted.

        So ``AuthService`` calls ``verify``, ``set_password_hash`` and
        ``apply_verified_password_hash`` on the entity it gets back, structurally,
        without ever naming the type.

        The real fix is a capability-shaped port: one this context *owns*, that
        declares those methods, satisfied structurally by the user context's
        repository. That is a second description of one repository, so it is a
        decision about where the capability belongs rather than a mechanical
        narrowing, and it is left to Phase 9 rather than done under time
        pressure. See ``docs/REVIEW.md``.
        """
        ...

    @property
    def session_repo(self) -> object:
        """Session capability, borrowed from the user context.

        The ``UserSession`` record belongs to the user context; creation,
        rotation and revocation are authentication's decisions about it. The
        returned value is a ``UserSession`` entity, detached, so a mutation needs
        an explicit ``save``.

        ``object`` for the same R2 reason as ``user_repo``.
        """
        ...
