"""
Eventlet + psycogreen bootstrap.

Must be the FIRST import in every process entry point (wsgi.py, app.py).

Under `gunicorn -k eventlet`, eventlet.monkey_patch(os=False) is already
applied in init_process BEFORE this module loads — the guard below prevents
the documented double-patch corruption that previously broke telegram's
patcher.original() usage. In dev mode (direct python app.py), the guard
triggers the first-and-only monkey_patch call.

psycogreen.eventlet.patch_psycopg() installs a wait-callback so libpq's
blocking I/O yields to the eventlet hub. Without this the entire worker
freezes on every DB roundtrip.
"""
import eventlet

if not eventlet.patcher.is_monkey_patched('socket'):
    eventlet.monkey_patch(os=False)

from psycogreen.eventlet import patch_psycopg
patch_psycopg()
