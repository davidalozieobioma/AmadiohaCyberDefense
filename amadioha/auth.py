"""Authentication and user management module."""

import hashlib
import secrets
import re
import base64
import hmac
import struct
import time
from typing import Optional, Dict
from amadioha import database


COMMON_PASSWORDS = {
    "password", "password123", "123456", "12345678", "qwerty", "qwerty123",
    "admin", "admin123", "letmein", "welcome", "iloveyou", "abc123"
}


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2."""
    salt = secrets.token_hex(32)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${pwd_hash.hex()}"


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify a password against stored hash."""
    try:
        salt, pwd_hash = stored_hash.split('$')
        pwd_check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return pwd_check.hex() == pwd_hash
    except:
        return False


def validate_username(username: str) -> tuple[bool, str]:
    """Validate username format."""
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 32:
        return False, "Username must be at most 32 characters"
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "Username can only contain alphanumeric characters, underscores, and hyphens"
    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    """Validate password strength."""
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    if len(password) > 128:
        return False, "Password must be at most 128 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password must contain at least one symbol"
    if password.lower() in COMMON_PASSWORDS:
        return False, "Password is too common"
    return True, ""


def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def register_user(username: str, password: str, email: str, role: str = 'user') -> tuple[bool, str, int]:
    """Register a new user."""
    # Validate inputs
    valid_username, msg = validate_username(username)
    if not valid_username:
        return False, msg, -1
    
    valid_password, msg = validate_password(password)
    if not valid_password:
        return False, msg, -1
    
    if not validate_email(email):
        return False, "Invalid email format", -1
    
    # Hash password
    password_hash = hash_password(password)
    
    # Create user
    user_id = database.create_user(username, password_hash, email, role=role)
    
    if user_id == -1:
        return False, "Username already exists", -1
    
    return True, "User registered successfully", user_id


def login_user(username: str, password: str, mfa_code: Optional[str] = None) -> tuple[bool, str, Optional[Dict], bool]:
    """Login a user."""
    user = database.get_user_by_username(username)
    
    if not user:
        return False, "Username or password incorrect", None, False
    
    if not verify_password(user['password_hash'], password):
        return False, "Username or password incorrect", None, False

    if user.get('mfa_enabled'):
        if not mfa_code:
            return False, "MFA code required", None, True
        if not verify_totp(user.get('mfa_secret') or "", mfa_code):
            return False, "Invalid MFA code", None, True
    
    # Update last login
    database.update_user_last_login(user['id'])
    
    # Return user info without password hash
    user_info = {
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'role': user['role'],
        'created_at': user['created_at'],
        'last_login': user['last_login']
    }
    
    return True, "Login successful", user_info, False


def generate_api_token(user_id: int) -> str:
    """Generate an API token for a user."""
    token = secrets.token_urlsafe(32)
    # In production, store this in database with expiration
    return token


def generate_mfa_secret() -> str:
    """Generate a base32 MFA secret."""
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode('utf-8').replace('=', '')


def get_totp_token(secret: str, for_time: Optional[int] = None, digits: int = 6, interval: int = 30) -> str:
    """Generate TOTP token for a secret."""
    if not secret:
        return ""
    if for_time is None:
        for_time = int(time.time())

    key = base64.b32decode(secret + '=' * ((8 - len(secret) % 8) % 8))
    counter = int(for_time / interval)
    msg = struct.pack('>Q', counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Verify a TOTP code within a time window."""
    code = (code or "").strip()
    if not code.isdigit():
        return False

    now = int(time.time())
    for offset in range(-window, window + 1):
        if get_totp_token(secret, now + offset * 30) == code:
            return True
    return False


if __name__ == "__main__":
    # Test user registration
    success, msg, uid = register_user("testuser", "TestPass123", "test@example.com")
    print(f"Register: {success}, {msg}, ID: {uid}")
    
    # Test login
    success, msg, user = login_user("testuser", "TestPass123")
    print(f"Login: {success}, {msg}, {user}")
