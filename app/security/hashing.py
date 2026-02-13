"""
Password hashing using Argon2.
Industry-standard secure password hashing with configurable parameters.
"""
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash

# Initialize Argon2 with secure parameters
ph = PasswordHasher(
    time_cost=2,      # Number of iterations
    memory_cost=65536,  # Memory in KiB (64 MB)
    parallelism=4,     # Number of parallel threads
    hash_len=32,       # Length of the hash in bytes
    salt_len=16        # Length of random salt
)


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2.
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password string
    """
    return ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        plain_password: Plain text password to verify
        hashed_password: Stored hash to verify against
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        ph.verify(hashed_password, plain_password)
        # Check if rehashing is needed (parameters changed)
        if ph.check_needs_rehash(hashed_password):
            # In production, trigger a background rehash task
            pass
        return True
    except (VerifyMismatchError, InvalidHash):
        return False