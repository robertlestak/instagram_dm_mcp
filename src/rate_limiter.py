"""
Rate limiter for Instagram MCP tools.

Why this exists: Instagram's anti-abuse system flags accounts on action
velocity (DMs, likes, follows). Even legitimate agent use can trigger
"action blocks" or permanent bans. This module enforces hard caps well
below Instagram's documented thresholds plus jitter to mimic human pacing.

State persists across server restarts to ~/.instagram-mcp-rate-limits.json
so a relaunch does not reset the daily budget. Reserving a slot is serialised
by ~/.instagram-mcp-rate-limits.json.lock across both threads and processes,
since the HTTP transport lets several callers share one server.

Per-category defaults (conservative; Instagram's real limits are higher):

  category   per_minute  per_hour  per_day  jitter
  dm_send         2          20       80    1.5-4.0s
  like            6          30      200    0.5-2.0s
  search         30         200     1000    0.0-0.5s
  lookup         30         300     2000    0.0-0.5s
  modify         10         100      500    0.0-0.5s
  login           4          10       20    0.0-0.5s

Override any cap via env var, e.g.:
  IG_RATE_LIMIT_DM_SEND_PER_DAY=40
  IG_RATE_LIMIT_LIKE_PER_HOUR=15
"""
from __future__ import annotations

import functools
import json
import logging
import os
import random
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Tuple

try:  # POSIX only; the in-process lock still applies without it.
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_STATE_PATH = Path.home() / ".instagram-mcp-rate-limits.json"
_LOCK_PATH = _STATE_PATH.with_name(_STATE_PATH.name + ".lock")
_THREAD_LOCK = threading.Lock()

# Mirror of the state, and whether the file is currently writable. Together they
# keep the caps enforced when the volume is not writable, instead of failing open.
_MEMORY_STATE: Dict[str, List[float]] = {}
_PERSISTENCE_OK = True

DEFAULTS: Dict[str, Dict[str, Any]] = {
    "dm_send": {"per_minute": 2,  "per_hour": 20,  "per_day": 80,   "jitter": (1.5, 4.0)},
    "like":    {"per_minute": 6,  "per_hour": 30,  "per_day": 200,  "jitter": (0.5, 2.0)},
    "search":  {"per_minute": 30, "per_hour": 200, "per_day": 1000, "jitter": (0.0, 0.5)},
    "lookup":  {"per_minute": 30, "per_hour": 300, "per_day": 2000, "jitter": (0.0, 0.5)},
    "modify":  {"per_minute": 10, "per_hour": 100, "per_day": 500,  "jitter": (0.0, 0.5)},
    # Sign-in is the most ban-prone action, so the hour/day caps stay tight. The
    # per-minute cap has to leave room for a person mistyping a 2FA code, though:
    # codes expire in ~30s, so anything stricter would expire the replacement
    # code while the caller waits and make the flow impossible to complete.
    "login":   {"per_minute": 4,  "per_hour": 10,  "per_day": 20,   "jitter": (0.0, 0.5)},
}


def _env_override(category: str, key: str, default: int) -> int:
    var = f"IG_RATE_LIMIT_{category.upper()}_{key.upper()}"
    raw = os.environ.get(var)
    if raw is None:
        return default
    try:
        value = int(raw)
        if value <= 0:
            return default
        return value
    except ValueError:
        return default


def _get_limits(category: str) -> Dict[str, Any]:
    d = DEFAULTS[category]
    return {
        "per_minute": _env_override(category, "per_minute", d["per_minute"]),
        "per_hour":   _env_override(category, "per_hour",   d["per_hour"]),
        "per_day":    _env_override(category, "per_day",    d["per_day"]),
        "jitter":     d["jitter"],
    }


@contextmanager
def _state_lock() -> Iterator[None]:
    """Serialise the read-modify-write of the state file.

    Two layers, because there are two ways to race. FastMCP dispatches sync
    tools onto a thread pool, so one process can be inside here twice at once;
    and several processes can share one state file (a mounted volume, or
    auth.py running alongside the server). Unserialised, two callers read the
    same counts, both append, and the second write erases the first
    reservation — under-counting the very budget this module exists to enforce.

    A dedicated lock file is used rather than the state file itself, because
    _save_state replaces the state file's inode and would drop the lock with it.
    """
    with _THREAD_LOCK:
        if fcntl is None:
            yield
            return
        try:
            fd = os.open(_LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Could not open the rate-limit lock file (%s); falling back to the "
                "in-process lock, which does not serialise other processes.", exc
            )
            yield
            return
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError as exc:
                # Some filesystems (certain NFS mounts) refuse locks. Degrade to
                # the in-process lock rather than failing the caller's tool call:
                # one process still serialises correctly, which is the common case.
                logger.warning(
                    "Could not take the rate-limit file lock (%s); serialising within "
                    "this process only.", exc
                )
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            finally:
                os.close(fd)


def _load_state() -> Dict[str, List[float]]:
    if not _PERSISTENCE_OK:
        # The file is unwritable, so it is stale by definition. Reading it would
        # hand back budget that was already spent, letting every call past the
        # cap — the module would look like it was working while enforcing
        # nothing. The in-memory copy is authoritative until writes recover.
        return {k: list(v) for k, v in _MEMORY_STATE.items()}
    if not _STATE_PATH.exists():
        return {}
    try:
        data = json.loads(_STATE_PATH.read_text())
        return {k: [float(t) for t in v] for k, v in data.items() if isinstance(v, list)}
    except Exception as exc:
        logger.warning("Could not load rate-limit state, starting fresh: %s", exc)
        return {}


def _save_state(state: Dict[str, List[float]]) -> bool:
    """Persist the reservation. Returns whether it reached disk.

    Write-then-rename: a crash partway through a plain write would leave
    unparseable JSON, and _load_state treats that as "start fresh" — silently
    handing back a full day's budget. os.replace is atomic on POSIX.

    The in-memory mirror is kept current either way, so that a write failure
    downgrades this from "limits enforced across restarts" to "limits enforced
    for the life of this process" rather than to no limits at all.
    """
    global _PERSISTENCE_OK
    _MEMORY_STATE.clear()
    _MEMORY_STATE.update({k: list(v) for k, v in state.items()})

    tmp = _STATE_PATH.with_name(f"{_STATE_PATH.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(state))
        os.replace(tmp, _STATE_PATH)
        _PERSISTENCE_OK = True
        return True
    except Exception as exc:
        if _PERSISTENCE_OK:  # log the transition once, not on every call
            logger.error(
                "Cannot persist rate-limit state (%s). Still enforcing limits from "
                "memory, but the budget will reset on restart — fix the volume.", exc
            )
        _PERSISTENCE_OK = False
        try:
            tmp.unlink()
        except OSError:
            pass
        return False


def _prune(timestamps: List[float], now: float, window_s: int) -> List[float]:
    cutoff = now - window_s
    return [t for t in timestamps if t >= cutoff]


def _fmt_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"


def _check_budget(
    category: str,
    limits: Dict[str, Any],
    state: Dict[str, List[float]],
) -> Tuple[bool, str, int, Dict[str, int]]:
    """Returns (ok, reason_if_blocked, retry_after_seconds, current_counts)."""
    now = time.time()
    pruned_day = _prune(state.get(category, []), now, 24 * 3600)
    state[category] = pruned_day

    counts: Dict[str, int] = {}
    for window_name, window_s in (("per_minute", 60), ("per_hour", 3600), ("per_day", 86400)):
        in_window = _prune(pruned_day, now, window_s)
        counts[window_name] = len(in_window)

    for window_name, window_s in (("per_minute", 60), ("per_hour", 3600), ("per_day", 86400)):
        in_window = _prune(pruned_day, now, window_s)
        limit = limits[window_name]
        if len(in_window) >= limit:
            oldest = min(in_window)
            retry_after = int((oldest + window_s) - now) + 1
            label = window_name.replace("per_", "")
            return (
                False,
                f"{category} hit {limit}/{label} cap (currently {len(in_window)}). Retry in {_fmt_duration(retry_after)}.",
                retry_after,
                counts,
            )
    return (True, "", 0, counts)


def rate_limited(category: str) -> Callable[[Callable[..., Dict[str, Any]]], Callable[..., Dict[str, Any]]]:
    """Decorator: enforce per-category limits and apply jitter before the call.

    Returns a structured error dict to the MCP client when blocked instead of
    raising, so the agent can surface "try again in 4h 12m" to the user
    instead of failing opaquely.
    """
    if category not in DEFAULTS:
        raise ValueError(f"Unknown rate-limit category: {category}")

    def decorator(func: Callable[..., Dict[str, Any]]) -> Callable[..., Dict[str, Any]]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
            limits = _get_limits(category)
            # Checking the budget and consuming a slot has to be one atomic
            # step, or two callers both pass a check that only had room for one.
            with _state_lock():
                state = _load_state()
                ok, reason, retry_after, current = _check_budget(category, limits, state)
                if ok:
                    state.setdefault(category, []).append(time.time())
                    _save_state(state)
            if not ok:
                logger.warning("Rate limit blocked %s: %s", func.__name__, reason)
                return {
                    "success": False,
                    "rate_limited": True,
                    "category": category,
                    "message": (
                        "Rate limit hit to protect this Instagram account from being "
                        f"flagged for automation: {reason}"
                    ),
                    "retry_after_seconds": retry_after,
                    "limits": {k: limits[k] for k in ("per_minute", "per_hour", "per_day")},
                    "current": current,
                }
            # Jitter sleeps outside the lock: a 4-second dm_send pause held
            # under it would serialise every other tool in the server.
            lo, hi = limits["jitter"]
            if hi > 0:
                time.sleep(random.uniform(lo, hi))
            return func(*args, **kwargs)
        return wrapper
    return decorator
