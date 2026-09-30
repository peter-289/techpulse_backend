"""Registration input rules.

``check_by_email``, ``check_by_username`` and ``map_integrity_error`` used to live
here. All three were dead:

* the two ``check_by_*`` helpers have had zero call sites since before this
  refactor began;
* ``map_integrity_error`` stopped being used when the user repository took over
  translating ``IntegrityError`` into ``DuplicateUserError``, which is the only
  place the driver is visible.

They are deleted rather than left as dead code. Password strength validation is
kept, and is shared: both this context's ``UserService`` and the authentication
context's password-reset flow enforce the same policy.
"""

from app.exceptions.exceptions import DomainError

# ============== VALIDATE PASSWORD ====================
# Password strength validation
def validate_password_strength(new_password: str) -> None:
    """Validate password strength according to defined criteria.""" 
    if not isinstance(new_password, str):
            raise DomainError("Password must be text")
    if len(new_password) < 8:
            raise DomainError("Password must be at least 8 characters long")
    if not any(char.isdigit() for char in new_password):
            raise DomainError("Password must contain at least one digit")
    if not any(char.isupper() for char in new_password):
            raise DomainError("Password must contain at least one uppercase letter")
    if not any(char.islower() for char in new_password):
            raise DomainError("Password must contain at least one lowercase letter")

