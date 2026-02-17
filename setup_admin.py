#!/usr/bin/env python3
"""Create initial admin account."""

import sys
sys.path.insert(0, '.')

from amadioha import auth

# Create admin account
username = "admin"
email = "davidalozieobioma@gmail.com"
password = "Amadioha@2026#Security"

success, msg, user_id = auth.register_user(username, password, email, role='admin')

if success:
    print("✅ Admin account created successfully!")
    print(f"   Username: {username}")
    print(f"   Email: {email}")
    print(f"   Password: {password}")
    print(f"   User ID: {user_id}")
    print("\n🔗 Login at: http://127.0.0.1:5000/login")
else:
    print(f"❌ Error: {msg}")

sys.exit(0 if success else 1)
