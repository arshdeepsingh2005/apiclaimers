"""
Main API routes (no HTML rendering).
"""
from pathlib import Path
from urllib.parse import urlparse

from flask import Blueprint, Response, jsonify, request, send_from_directory

from app.config import Config
from app.utils.decoy import generate_decoy_response

main_bp = Blueprint('main', __name__)


def _relay_domain_allowed(url: str) -> bool:
    """Return True if the URL's host is in RELAY_ALLOWED_DOMAINS."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        host = parsed.netloc.split(":")[0].lower()
        return host in Config.RELAY_ALLOWED_DOMAINS
    except Exception:
        return False


@main_bp.route('/health')
def health():
    """Health check endpoint for UptimeRobot monitoring."""
    return jsonify({
        'status': 'healthy',
        'service': 'code-server'
    }), 200


@main_bp.route('/relay')
def relay():
    """Fetch a URL and return its content (CSP bypass). Only allowed domains may be fetched.

    Disabled by default (RELAY_ENABLED): this is an unauthenticated allowlisted
    proxy the license-only userscript never calls, so it stays dark in
    production to remove the SSRF/open-proxy surface. When off it returns the
    decoy response (indistinguishable from any non-route)."""
    if not Config.RELAY_ENABLED:
        return generate_decoy_response()

    target_url = request.args.get('url')
    if not target_url:
        return jsonify({'error': 'Missing url parameter'}), 400

    if not _relay_domain_allowed(target_url):
        return jsonify({'error': 'Domain not allowed for relay'}), 403

    try:
        import requests
        response = requests.get(target_url, timeout=10)
        return Response(
            response.content,
            status=response.status_code,
            headers={'Content-Type': response.headers.get('Content-Type', 'text/html')}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Decoy routes (intentionally added, no real purpose)
@main_bp.route('/')
def index():
    """Decoy route."""
    return generate_decoy_response()


@main_bp.route('/dashboard')
def dashboard():
    """Decoy route."""
    return generate_decoy_response()


@main_bp.route('/admin')
def admin():
    """Decoy route."""
    return generate_decoy_response()


@main_bp.route('/api')
def api_index():
    """Decoy route."""
    return generate_decoy_response()


@main_bp.route('/status')
def status():
    """Decoy route."""
    return generate_decoy_response()


def _serve_test_page(filename: str):
    """Serve a local test harness page — ONLY in debug. In production these
    diagnostic pages are not exposed (return the decoy response instead)."""
    if not Config.DEBUG:
        return generate_decoy_response()
    tests_dir = Path(__file__).parent.parent.parent / 'tests'
    return send_from_directory(str(tests_dir), filename)


@main_bp.route('/test')
def test_page():
    """Socket.IO test page (debug-only)."""
    return _serve_test_page('socket_test.html')


@main_bp.route('/sse-test')
def sse_test_page():
    """SSE /embed-stream test page (debug-only)."""
    return _serve_test_page('sse_test.html')


@main_bp.route('/load-test')
def load_test_page():
    """SSE load test page (debug-only)."""
    return _serve_test_page('load_test_sse.html')


