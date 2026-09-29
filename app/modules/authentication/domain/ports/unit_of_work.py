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
        """User lookup capability, borrowed from the user context.

        ``object`` until Phase 6 introduces the User aggregate, at which point
        this narrows to the user context's ``UserRepository`` protocol and the
        returned type stops being an ORM row.
        """
        ...

    @property
    def session_repo(self) -> object:
        """Session lifecycle capability, borrowed from the user context.

        Session creation, rotation and revocation are authentication's
        concerns, but the ``UserSession`` record belongs to the user context.
        """
        ...
