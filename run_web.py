#!/usr/bin/env python
"""Launcher script for Amadioha Web Dashboard."""

from amadioha.web import run_server
import sys

if __name__ == '__main__':
    print("=" * 60)
    print("  Amadioha Cyber Defense — Web Dashboard")
    print("=" * 60)
    print()
    print("🚀 Starting web server...")
    print("📱 Dashboard: http://localhost:5000")
    print("🛑 Press Ctrl+C to stop the server")
    print()
    try:
        run_server(host='127.0.0.1', port=5000, debug=True)
    except KeyboardInterrupt:
        print("\n✓ Server stopped.")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)
