"""Production WSGI server configuration using Waitress (Windows-compatible)."""

from amadioha import web
import logging

if __name__ == '__main__':
    # Configure production logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    try:
        from waitress import serve
        print("=" * 60)
        print("  Amadioha Cyber Defense — Production Server")
        print("=" * 60)
        print()
        print("🚀 Starting production server with Waitress...")
        print("📱 Server: http://0.0.0.0:8080")
        print("🔒 Running in production mode")
        print("🛑 Press Ctrl+C to stop")
        print()

        # Serve application with Waitress
        # threads=4 for handling concurrent requests
        # channel_timeout=60 for longer-running operations
        serve(
            web.app,
            host='0.0.0.0',
            port=8080,
            threads=4,
            channel_timeout=60,
            url_scheme='http'
        )
    except ImportError:
        print("❌ Waitress not installed!")
        print("Install it with: pip install waitress")
    except KeyboardInterrupt:
        print("\n\n✅ Server stopped gracefully")
