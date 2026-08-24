# Real-Time Code Broadcasting System

Production-ready Flask application for real-time code broadcasting with HTTP REST APIs, WebSocket (Socket.IO), and Server-Sent Events (SSE).

## Quick Start

1. **Set Database URL (required):**
```bash
export DATABASE_URL="postgresql://user:pass@host:5432/dbname"
```

2. **Install Dependencies:**
```bash
pip install -r requirements.txt
```

3. **Start Server:**
```bash
python app.py  # Development
# Or for production:
gunicorn --config gunicorn.conf.py wsgi:app
```

## Key Endpoints

- `POST /api/ingest` - Send codes via HTTP
- `GET /api/users/<username>/verify` - Verify username
- `GET /health` - Health check
- WebSocket: `/events` namespace
- SSE: `/embed-stream`, `/events` (SSE stream)

## Testing

```bash
python test_sse_helper.py test-all bharat
```

## Production Deployment

Set `DATABASE_URL` environment variable in your deployment platform (e.g., Render).
