from app.exceptions.exceptions import ConflictError, DomainError

def check_by_email(user) -> None:
    if user:
        raise ConflictError("Email already exists!")
    return None
    

def check_by_username(user) -> None:
    if user:
        raise ConflictError("Username already exixts!")
    return None

def map_integrity_error(message: str) -> ConflictError:
    if "username" in message:
        return ConflictError("Username already exists!")
    if "email" in message:
        return ConflictError("Email already exists!")


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

