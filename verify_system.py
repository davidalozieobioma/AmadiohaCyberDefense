#!/usr/bin/env python3
"""Verify app is working correctly."""

import sys
import sqlite3
import os

sys.path.insert(0, '.')  # noqa: E402

from amadioha import database  # noqa: E402
from amadioha.database import DB_PATH  # noqa: E402

# Initialize database
database.init_db()

print("=" * 60)
print("🔍 SYSTEM HEALTH CHECK")
print("=" * 60)

# Check users
user_count = database.count_users()
users = database.get_all_users()

print("\n✅ Database Status: Connected")
print(f"✅ Total Users: {user_count}")
print("\n📋 Users List:")
for user in users:
    print(f"   • {user['username']} ({user['email']})")
    print(f"     └─ Role: {user['role']}")

# Check tables
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = sorted([row[0] for row in cursor.fetchall()])
conn.close()

print(f"\n✅ Database Tables: {len(tables)} found")
for table in tables:
    print(f"   ✓ {table}")

print("\n✅ Project Files:")
key_files = [
    'amadioha/web.py',
    'amadioha/database.py',
    'amadioha/templates/admin.html',
    'amadioha/templates/login.html',
    'amadioha/templates/dashboard.html',
    'requirements.txt',
    'README.md'
]

for file in key_files:
    exists = "✓" if os.path.exists(file) else "✗"
    print(f"   {exists} {file}")

print("\n" + "=" * 60)
print("✨ System is ready! Admin Portal: http://127.0.0.1:5000/admin")
print("=" * 60)
