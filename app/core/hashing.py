from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
import unicodedata
from typing import Optional


ph = PasswordHasher(
    time_cost=3,
    memory_cost=102400,
    parallelism=4
)

# Password Manager Class(Not sure if it is really needed)
class PasswordManager:
      def __init__(self):
          pass
      
      def _normalize_pass(password: str) -> str:
           return unicodedata.normalize("NFKC", password)
       
      def hash_pass(self, password: str)->str:
           normalized_pass = self._normalize_pass(password)
           hashed_pass = ph.hash(normalized_pass)
           return hashed_pass
      
      def verify_passwd(self, stored_hash: str, passwd: str):
          password = self._normalize_pass(passwd)
          try:
              ph.verify(stored_hash, password)
          except VerifyMismatchError:
              return None
          except InvalidHashError:
              raise RuntimeError("Invalid password hash!")
          
          # Check if stored hash needs rehash
          if ph.check_needs_rehash(stored_hash):
              stored_hash = ph.hash(password)
          return stored_hash
          





def _normalize_password(password: str) -> str:
    """Normalize password using NFKC Unicode normalization.
    
    Args:
        password: The plain text password to normalize.
        
    Returns:
        The normalized password string.
    """
    return unicodedata.normalize("NFKC", password)


def hash_password(password: str) -> str:
    """Hash a password using Argon2 algorithm.
    
    Args:
        password: The plain text password to hash.
        
    Returns:
        The hashed password string.
    """
    password = _normalize_password(password)
    hashed = ph.hash(password)
    return hashed


def verify_password(stored_hash: str, password: str) -> Optional[str]:
    """Verify a password against a stored hash and optionally rehash.
    
    Args:
        stored_hash: The previously hashed password.
        password: The plain text password to verify.
        
    Returns:
        A new hash if rehashing is needed, the original hash if password matches,
        or None if verification fails.
        
    Raises:
        RuntimeError: If the stored hash is invalid.
    """
    password = _normalize_password(password)
    try:
        ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return None
    except InvalidHashError:
        raise RuntimeError("Stored password hash is invalid!")
    if ph.check_needs_rehash(stored_hash):
        return ph.hash(password)
    return stored_hash




