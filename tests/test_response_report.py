"""Unit tests for the broadcast response report (F-report) in tmc_routes.

These exercise the report store + helpers WITHOUT a running server: eventlet
timers are captured (not spawned) and admin pushes are captured (not sent), so
the delta math, composite claimed-dedup, window-extension, orphan-timer guard,
pre-emit ordering, and bounds are all asserted deterministically.

Requires the app deps to be importable (Flask/eventlet/flask_socketio). A pure,
dependency-free variant of these same assertions lives in the plan's scratchpad
harness (AST-extracts the functions) for environments without those deps.
"""
import types

import pytest

# Requires the app deps (Flask/flask_socketio) + eventlet; skip cleanly if absent.
tmc = pytest.importorskip("app.routes.tmc_routes")
eventlet = pytest.importorskip("eventlet")


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Reset the store, capture spawns + pushes, control the monotonic clock,
    and configure one admin — restored automatically after each test."""
    tmc._response_tallies.clear()

    # The report functions do a LOCAL `import eventlet` then call
    # eventlet.spawn_after(...), so patch the real eventlet module.
    spawns = []
    monkeypatch.setattr(
        eventlet, "spawn_after",
        lambda delay, fn, *a: spawns.append((delay, fn, a)) or ("t", delay, fn, a),
    )

    sent = []
    monkeypatch.setattr(tmc, "notify_bot_service", lambda tid, msg: sent.append((tid, msg)))
    monkeypatch.setattr(tmc, "_ADMIN_TELEGRAM_IDS", {12345})

    clock = types.SimpleNamespace(t=1000.0)
    monkeypatch.setattr(tmc.time, "monotonic", lambda: clock.t)

    yield types.SimpleNamespace(spawns=spawns, sent=sent, clock=clock)

    tmc._response_tallies.clear()


def _res(username, claimed=False, error=""):
    return {"username": username, "claimed": claimed, "error": error}


def _fold(lic, code, r):
    with tmc._claim_collectors_lock:
        tmc._fold_response_tally(lic, code, r)


def _fire_last(env):
    delay, fn, args = env.spawns[-1]
    fn(*args)


# --------------------------------------------------------------------------- #
def test_response_category():
    assert tmc._response_category(True, "x") == "claimed"
    assert tmc._response_category(False, "already_claimed") == "already_claimed"
    assert tmc._response_category(False, "") == "no_result"
    assert tmc._response_category(False, "Weird Error!!") == "weird_error__"


def test_sanitize_label():
    assert tmc._report_sanitize_label("ABC def-!") == "abc_def__"
    assert tmc._report_sanitize_label("") == "unknown"
    assert len(tmc._report_sanitize_label("x" * 50)) == 24


def test_max_cats_overflow_to_other():
    tmc._schedule_or_extend("CATS")
    for i in range(tmc._REPORT_MAX_CATS + 5):
        _fold("L", "CATS", _res(f"u{i}", error=f"err{i}"))
    e = tmc._response_tallies["CATS"]
    assert len([k for k in e["counts"] if k != "other"]) <= tmc._REPORT_MAX_CATS
    assert "other" in e["counts"]
    assert e["total"] == tmc._REPORT_MAX_CATS + 5


def test_composite_claimed_dedup():
    tmc._schedule_or_extend("ABC")
    _fold("licA", "ABC", _res("user1", claimed=True))
    _fold("licA", "ABC", _res("user2", claimed=True))
    _fold("licA", "ABC", _res("user1", claimed=True))          # dup -> ignored
    e = tmc._response_tallies["ABC"]
    assert e["counts"]["claimed"] == 2
    _fold("licB", "ABC", _res("user1", claimed=True))          # other license
    assert e["counts"]["claimed"] == 3
    _fold("licA", "ABC", _res("user1", error="already_claimed"))
    _fold("licA", "ABC", _res("user1", error="already_claimed"))
    assert e["counts"]["already_claimed"] == 2                 # non-claimed not deduped


def test_delta_reports(request):
    env = request.getfixturevalue("_isolate")
    tmc._schedule_or_extend("DEL")
    _fold("L", "DEL", _res("a", claimed=True))
    _fold("L", "DEL", _res("b", error="not_found"))
    env.clock.t += tmc._REPORT_WINDOW
    _fire_last(env)
    assert len(env.sent) == 1
    assert "New responses: 2" in env.sent[-1][1]
    assert "Claimed: 1" in env.sent[-1][1]

    env.sent.clear()
    tmc._schedule_or_extend("DEL")                 # fresh window, same baseline
    _fold("L", "DEL", _res("c", claimed=True))
    env.clock.t += tmc._REPORT_WINDOW
    _fire_last(env)
    assert len(env.sent) == 1
    assert "New responses: 1" in env.sent[-1][1]
    assert "Σ 3 total" in env.sent[-1][1]


def test_zero_delta_no_send(request):
    env = request.getfixturevalue("_isolate")
    tmc._schedule_or_extend("EMPTY")
    env.clock.t += tmc._REPORT_WINDOW
    _fire_last(env)
    assert env.sent == []


def test_window_extension_single_timer(request):
    env = request.getfixturevalue("_isolate")
    t0 = env.clock.t
    tmc._schedule_or_extend("EXT")
    e = tmc._response_tallies["EXT"]
    assert e["deadline"] == pytest.approx(t0 + 10)
    assert len(env.spawns) == 1
    env.clock.t = t0 + 5
    tmc._schedule_or_extend("EXT")
    assert e["deadline"] == pytest.approx(t0 + 15)
    assert len(env.spawns) == 1                    # no new timer
    env.clock.t = t0 + 12
    tmc._schedule_or_extend("EXT")
    assert e["deadline"] == pytest.approx(t0 + 22)
    # early fire -> reschedule, not finalize
    delay, fn, args = env.spawns[0]
    env.clock.t = t0 + 10
    fn(*args)
    assert env.sent == []
    assert len(env.spawns) == 2
    _fold("L", "EXT", _res("z", claimed=True))
    env.clock.t = t0 + 22
    _fire_last(env)
    assert len(env.sent) == 1


def test_hard_max_cap(request):
    env = request.getfixturevalue("_isolate")
    t0 = env.clock.t
    tmc._schedule_or_extend("CAP")
    for step in (5, 12, 20, 28):
        env.clock.t = t0 + step
        tmc._schedule_or_extend("CAP")
    e = tmc._response_tallies["CAP"]
    assert e["deadline"] <= t0 + tmc._REPORT_HARD_MAX + 1e-6


def test_orphan_timer_gen_guard(request):
    env = request.getfixturevalue("_isolate")
    tmc._schedule_or_extend("ORPH")
    gen1 = tmc._response_tallies["ORPH"]["gen"]
    _fold("L", "ORPH", _res("old", claimed=True))
    timerA = env.spawns[-1]
    assert timerA[2] == ("ORPH", gen1)
    for i in range(tmc._REPORT_MAX_CODES):         # evict via LRU flood
        tmc._schedule_or_extend(f"flood{i}")
    assert "ORPH" not in tmc._response_tallies
    tmc._schedule_or_extend("ORPH")                # recreate
    e2 = tmc._response_tallies["ORPH"]
    assert e2["gen"] != gen1
    _fold("L", "ORPH", _res("new", claimed=True))
    timerB = env.spawns[-1]
    env.sent.clear()
    n_spawns = len(env.spawns)
    env.clock.t += 100
    timerA[1](*timerA[2])                          # fire orphan A
    assert env.sent == []
    assert len(env.spawns) == n_spawns             # no reschedule
    assert e2["counts"].get("claimed") == 1 and e2["reported_total"] == 0
    timerB[1](*timerB[2])                          # fire current B
    assert len(env.sent) == 1 and "New responses: 1" in env.sent[-1][1]


def test_pre_emit_ordering_first_responder(request):
    env = request.getfixturevalue("_isolate")
    tmc._schedule_or_extend("ORD")                 # window opened pre-emit
    _fold("L", "ORD", _res("first", claimed=True)) # arrives mid-fanout
    env.clock.t += tmc._REPORT_WINDOW
    _fire_last(env)
    assert "Claimed: 1" in env.sent[-1][1]


def test_no_admin_is_noop(request, monkeypatch):
    env = request.getfixturevalue("_isolate")
    monkeypatch.setattr(tmc, "_ADMIN_TELEGRAM_IDS", set())
    tmc._schedule_or_extend("NOADMIN")
    assert "NOADMIN" not in tmc._response_tallies
    assert env.spawns == []


def test_claimed_users_hard_cap(request, monkeypatch):
    env = request.getfixturevalue("_isolate")
    monkeypatch.setattr(tmc, "_REPORT_MAX_CLAIMED_USERS", 3)
    tmc._schedule_or_extend("CAPU")
    for i in range(6):
        _fold("L", "CAPU", _res(f"user{i}", claimed=True))
    e = tmc._response_tallies["CAPU"]
    assert len(e["claimed_users"]) == 3
    assert e["counts"]["claimed"] == 6


def test_ttl_prune(request):
    env = request.getfixturevalue("_isolate")
    tmc._schedule_or_extend("STALE")
    assert "STALE" in tmc._response_tallies
    env.clock.t += tmc._REPORT_TTL + 1
    tmc._schedule_or_extend("FRESH")
    assert "STALE" not in tmc._response_tallies
    assert "FRESH" in tmc._response_tallies


def test_lru_cap(request):
    env = request.getfixturevalue("_isolate")
    for i in range(tmc._REPORT_MAX_CODES + 10):
        tmc._schedule_or_extend(f"c{i}")
    assert len(tmc._response_tallies) == tmc._REPORT_MAX_CODES
