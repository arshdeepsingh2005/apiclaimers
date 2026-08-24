"""
Development entry point (proxies to wsgi app).
"""
import app._bootstrap  # noqa: F401 — must be first
from wsgi import app

if __name__ == "__main__":
    from app import (
        socketio,
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

    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
