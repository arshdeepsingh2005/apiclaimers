"""
WSGI entry point for production.

The first import MUST be `app._bootstrap`. It is idempotent: under
`gunicorn -k eventlet` the monkey_patch call is skipped by its guard,
and psycogreen is applied so psycopg2 yields to the eventlet hub.
"""
import app._bootstrap  # noqa: F401 — must be first
import sys
import logging

# Configure logging to stdout (Render captures this)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

try:
    from app import create_app, socketio
    from app.utils.cloudflare import get_real_client_ip, is_cloudflare_request, get_cloudflare_ray_id
    app = create_app()
    
    @app.before_request
    def before_request():
        """Execute before each request - log Cloudflare info if available."""
        # Log Cloudflare information for debugging (optional)
        if is_cloudflare_request():
            client_ip = get_real_client_ip()
            ray_id = get_cloudflare_ray_id()
            # Uncomment below if you want to log every request (can be verbose)
            # logger.debug(f"Cloudflare request - IP: {client_ip}, Ray ID: {ray_id}")
    
except Exception as e:
    logger.error("=" * 60)
    logger.error("FATAL ERROR: Failed to create application")
    logger.error("=" * 60)
    logger.error(f"Error: {e}", exc_info=True)
    logger.error("=" * 60)
    # Re-raise so Gunicorn sees the error
    raise


if __name__ == "__main__":
    import os
    PORT = int(os.environ.get("PORT", 5000))
    # Use environment variable for debug mode, default to False for production
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    from app import (
        _start_sse_cleanup_thread,
        _start_active_disconnect_worker,
        _start_cache_sweep_worker,
        _start_license_activation_scanner,
    )
    _start_sse_cleanup_thread()
    _start_active_disconnect_worker(app)
    _start_cache_sweep_worker(app)
    try:
        from app.license_manager import rebuild_cache_from_db
        rebuild_cache_from_db()
    except Exception:
        pass
    _start_license_activation_scanner(app)

    socketio.run(app, host="0.0.0.0", port=PORT, debug=DEBUG)
