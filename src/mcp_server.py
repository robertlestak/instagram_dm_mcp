from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware
from instagrapi import Client
from instagrapi.exceptions import BadPassword, ChallengeRequired, TwoFactorRequired
import argparse
import sys
from typing import Optional, List, Dict, Any
import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import unquote
from dotenv import load_dotenv
import logging
from pathlib import Path

from rate_limiter import rate_limited

# Load environment variables from .env file
load_dotenv()

# Set up logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

INSTRUCTIONS = """
This server is used to send messages to a user on Instagram.

If a tool reports that the server is not signed in, call instagram_auth_status and do
exactly what its next_step says. Do not assume a 2FA code is needed — the server often
holds its own, and some accounts never get one. Never ask anyone to send you a password
or a session cookie; those are configured on the server and must not pass through here.
"""

client = Client()


class AuthState:
    """Where the Instagram session stands, as the running server sees it.

    Sign-in is deliberately not a startup precondition. The server has to keep
    serving when a session is missing or expired, because the alternative —
    exiting — means a supervised container restarts and retries the login every
    few minutes, and repeated failed logins are what get accounts banned. Here
    the process stays up, reports what it needs, and waits to be given it.
    """

    def __init__(self) -> None:
        self.authenticated: bool = False
        # unconfigured | needs_login | needs_2fa | bad_totp_seed | blocked | authenticated
        self.state: str = "unconfigured"
        self.detail: str = "The server has not attempted a sign-in yet."
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.totp_seed: Optional[str] = None
        # Credentials, all server-side only. None of these are ever accepted
        # through a tool call — see _adopt_sessionid for why that matters.
        self.sessionid: Optional[str] = None
        # Set once Instagram has rejected a code minted from the seed, so the
        # server stops offering "just try again" as the next step.
        self.totp_rejected: bool = False
        self.session_file: Optional[Path] = None
        self.session_dir: Optional[Path] = None

    @property
    def block_file(self) -> Optional[Path]:
        return self.session_dir / "login_blocked.json" if self.session_dir else None

    def set(self, state: str, detail: str) -> None:
        self.state = state
        self.detail = detail
        self.authenticated = state == "authenticated"


AUTH = AuthState()

# Tools that must stay reachable while signed out — they are how you sign in.
AUTH_TOOLS = {"instagram_auth_status", "instagram_login"}


class RequireAuth(Middleware):
    """Fail Instagram tools with an actionable message when signed out.

    Without this, every tool surfaces a different low-level instagrapi error
    when the session is missing, and the agent has no way to know that the fix
    is a sign-in rather than a retry.
    """

    async def on_call_tool(self, context, call_next):
        if context.message.name not in AUTH_TOOLS and not AUTH.authenticated:
            raise ToolError(
                f"Not signed in to Instagram ({AUTH.state}): {AUTH.detail} "
                f"Call instagram_auth_status for the next step."
            )
        return await call_next(context)


mcp = FastMCP(
   name="Instagram DMs",
   instructions=INSTRUCTIONS,
   middleware=[RequireAuth()],
)

UNRECOVERABLE_LOGIN_ERRORS = (TwoFactorRequired, BadPassword, ChallengeRequired)


def _record_block(err: BaseException) -> None:
    """Remember a login failure that only a human can clear.

    Read back on the next start so a restarting container does not re-attempt
    the same doomed login on a loop.
    """
    if not AUTH.block_file:
        return
    try:
        AUTH.block_file.write_text(json.dumps({
            "username": AUTH.username,
            "error": type(err).__name__,
            "detail": str(err),
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            # What the server had to work with at the time. If it gains a way to
            # produce a code later, the block no longer describes the situation.
            "had_totp_seed": bool(AUTH.totp_seed),
        }, indent=2))
    except Exception:  # noqa: BLE001
        logger.warning(f"Could not record the login block at {AUTH.block_file}")


def _read_block() -> Optional[Dict[str, Any]]:
    if not AUTH.block_file or not AUTH.block_file.exists():
        return None
    try:
        return json.loads(AUTH.block_file.read_text())
    except Exception:  # noqa: BLE001
        return {"error": "unknown", "detail": "unreadable block file"}


def _clear_block() -> None:
    if not AUTH.block_file:
        return
    try:
        AUTH.block_file.unlink()
    except FileNotFoundError:
        pass
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Could not clear {AUTH.block_file}: {e}")


def _save_session() -> bool:
    """Persist the session. Returns whether it actually reached disk.

    Persistence failing must never stop the server from serving: the sign-in
    itself succeeded, and the whole point of this module is that the process
    stays up and explains itself instead of exiting into a restart loop. An
    unwritable volume is exactly the case that used to kill startup here.
    """
    if not AUTH.session_file:
        return False
    try:
        client.dump_settings(AUTH.session_file)
        logger.info(f"Session saved to {AUTH.session_file}")
        return True
    except Exception as e:  # noqa: BLE001
        logger.error(
            f"Signed in, but could not save the session to {AUTH.session_file} ({e}). "
            f"Serving on the in-memory session; a restart will have to sign in again, "
            f"so make the volume writable."
        )
        return False


def _attempt_login(verification_code: str = "") -> Dict[str, Any]:
    """Log in, and translate the outcome into AuthState plus a tool-shaped dict."""
    if not AUTH.username or not AUTH.password:
        AUTH.set("unconfigured", "No username/password configured on the server.")
        return {"success": False, "state": AUTH.state, "message": AUTH.detail}

    # A TOTP seed makes 2FA fully headless: the code is derived here rather
    # than typed by a person, which is the only way an unattended restart can
    # get through 2FA on its own.
    used_generated_code = False
    if not verification_code and AUTH.totp_seed:
        try:
            verification_code = client.totp_generate_code(AUTH.totp_seed)
            used_generated_code = True
            logger.info("Generated a 2FA code from INSTAGRAM_TOTP_SEED")
        except Exception as e:  # noqa: BLE001
            # Do not fall through to a code-less login: Instagram answers that
            # with "2FA required", which reads as a rejected code and sends the
            # caller hunting for a fresh one when the seed is the actual problem.
            AUTH.set("bad_totp_seed", f"INSTAGRAM_TOTP_SEED is unusable: {e}")
            logger.error(
                f"Could not generate a code from INSTAGRAM_TOTP_SEED ({e}). Separators and "
                f"case are already normalised, so the value itself is not a base32 secret "
                f"(letters A-Z and digits 2-7). No login was attempted."
            )
            return {"success": False, "state": AUTH.state, "message": AUTH.detail}

    try:
        client.login(AUTH.username, AUTH.password, verification_code=verification_code)
    except TwoFactorRequired as e:
        _record_block(e)
        if used_generated_code:
            # The seed produced a well-formed code that Instagram rejected, so
            # the seed is wrong for this account. Retrying regenerates the same
            # wrong code — say so, or the caller loops.
            AUTH.totp_rejected = True
            AUTH.set(
                "needs_2fa",
                "Instagram rejected the code generated from INSTAGRAM_TOTP_SEED, so that "
                "seed does not belong to this account's authenticator.",
            )
            return {
                "success": False,
                "state": AUTH.state,
                "message": (
                    "The code generated from INSTAGRAM_TOTP_SEED was rejected. Calling this "
                    "again without a code will produce the same wrong code — the seed itself "
                    "needs fixing on the server, or set INSTAGRAM_SESSIONID instead. A single "
                    "code read from the user's authenticator can get in right now."
                ),
            }
        AUTH.set("needs_2fa", "Instagram wants a 2FA code for this sign-in.")
        return {
            "success": False,
            "state": AUTH.state,
            "message": (
                "Two-factor authentication required. Ask the user for the current "
                "6-digit code and call instagram_login again with verification_code set. "
                "Codes expire in about 30 seconds, so pass it promptly."
            ),
        }
    except UNRECOVERABLE_LOGIN_ERRORS as e:
        AUTH.set("blocked", f"{type(e).__name__}: {e}")
        _record_block(e)
        return {
            "success": False,
            "state": AUTH.state,
            "message": (
                f"Sign-in failed: {type(e).__name__}: {e}. This needs a person — check the "
                f"credentials, or open instagram.com and clear any pending challenge."
            ),
        }
    except Exception as e:  # noqa: BLE001
        AUTH.set("needs_login", f"{type(e).__name__}: {e}")
        return {"success": False, "state": AUTH.state, "message": f"Sign-in failed: {e}"}

    persisted = _save_session()
    _clear_block()
    AUTH.set(
        "authenticated",
        f"Signed in as @{AUTH.username}."
        + ("" if persisted else " The session could not be saved, so a restart will sign in again."),
    )
    logger.info(f"Signed in as @{AUTH.username}")
    return {"success": True, "state": AUTH.state, "message": AUTH.detail}


def _adopt_sessionid() -> bool:
    """Adopt a browser session supplied to the server as INSTAGRAM_SESSIONID.

    This is the way in for accounts whose 2FA is an approve-on-device push:
    Instagram issues no code for those, and the login API cannot wait for the
    tap, so a session established in a browser is the only thing that works.

    The value is read from the server's own environment and never crosses the
    MCP boundary. A sessionid is a bearer token for the entire account with a
    long life, so it must not pass through an agent, a tool call, or a chat
    transcript — unlike a 2FA code, it is worth stealing and reusable if it is.
    """
    if not AUTH.sessionid:
        return False

    logger.info("Adopting the session from INSTAGRAM_SESSIONID")
    try:
        client.login_by_sessionid(AUTH.sessionid)
    except Exception as e:  # noqa: BLE001
        logger.error(f"INSTAGRAM_SESSIONID was rejected ({type(e).__name__}: {e})")
        AUTH.set("needs_login", f"The configured sessionid was rejected: {type(e).__name__}.")
        return False

    # Resolve who we just became. The cookie carries the user id as its prefix,
    # which is the fallback when the user-info endpoint is unhappy.
    username = None
    try:
        username = client.account_info().username
    except Exception as e:  # noqa: BLE001
        logger.warning(f"account_info() after sessionid login failed: {e}")
        try:
            username = client.user_info_v1(int(AUTH.sessionid.split(":")[0])).username
        except Exception:  # noqa: BLE001
            username = AUTH.username

    if not username:
        AUTH.set("needs_login", "Signed in by sessionid but could not resolve the username.")
        return False

    # The sessionid may belong to a different account than the configured one,
    # so the session file follows the account actually obtained.
    AUTH.username = username
    if AUTH.session_dir:
        AUTH.session_file = AUTH.session_dir / f"{username}_session.json"
        try:
            (AUTH.session_dir / "current_user.txt").write_text(username)
        except Exception:  # noqa: BLE001
            pass

    persisted = _save_session()
    _clear_block()
    AUTH.set(
        "authenticated",
        f"Signed in as @{username} from a supplied browser session."
        + ("" if persisted else " The session could not be saved, so a restart will sign in again."),
    )
    logger.info(f"Signed in as @{username} via INSTAGRAM_SESSIONID")
    return True


def _load_session() -> bool:
    """Adopt an existing session file if it still works."""
    if not AUTH.session_file or not AUTH.session_file.exists():
        return False
    logger.info(f"Loading existing session from {AUTH.session_file}")
    try:
        client.load_settings(AUTH.session_file)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Could not read {AUTH.session_file}: {e}")
        return False
    try:
        info = client.account_info()
        AUTH.set("authenticated", f"Signed in as @{info.username} from a saved session.")
        logger.info(f"Session valid for @{info.username}")
        return True
    except Exception as e:  # noqa: BLE001
        # Instagram's mobile API frequently returns 467 on the user-info
        # endpoint for browser-derived sessions that still authorize other
        # calls, so a failed probe is not proof the session is dead.
        if AUTH.sessionid:
            # ...but a supplied browser session is known-good and costs no login
            # attempt, so prefer it over a saved session that just failed. Without
            # this, setting INSTAGRAM_SESSIONID to recover from an expired session
            # would be silently ignored in favour of the expired file.
            logger.warning(
                f"account_info() probe failed ({e}); preferring the supplied "
                f"INSTAGRAM_SESSIONID over the saved session."
            )
            return False
        logger.warning(f"account_info() probe failed ({e}); trusting the loaded session.")
        AUTH.set("authenticated", "Signed in from a saved session (probe inconclusive).")
        return True


def bootstrap_auth() -> None:
    """Get as far toward a usable session as possible, without ever exiting."""
    if _load_session():
        return

    # A supplied browser session outranks a password login: it is already past
    # whatever 2FA the account uses, so it neither prompts nor risks a failed
    # login against the account.
    if _adopt_sessionid():
        return

    if not AUTH.username or not AUTH.password:
        AUTH.set(
            "unconfigured",
            "No saved session, and no username/password configured. Run auth.py, or set "
            "INSTAGRAM_USERNAME and INSTAGRAM_PASSWORD.",
        )
        logger.error(AUTH.detail)
        return

    blocked = _read_block()
    if blocked:
        # A block records that the login could not be completed with what the
        # server had at the time. A TOTP seed configured since then is a new
        # capability — it can now produce the code it was missing — so the block
        # no longer describes the situation and is worth one fresh attempt. If
        # that attempt fails too, it is re-recorded with had_totp_seed set and
        # later starts stop trying.
        if AUTH.totp_seed and not blocked.get("had_totp_seed"):
            logger.info(
                "A TOTP seed is configured now, but the recorded block predates it — "
                "clearing it and retrying the sign-in once."
            )
            _clear_block()
        else:
            AUTH.set(
                "blocked",
                f"A previous sign-in failed with {blocked.get('error')} at {blocked.get('at')} "
                f"({blocked.get('detail')}). No login was attempted.",
            )
            logger.error(
                f"{AUTH.detail} Call the instagram_login tool (with a 2FA code if needed) "
                f"or run auth.py; either clears {AUTH.block_file}."
            )
            return

    logger.info("No usable session; attempting a fresh login...")
    result = _attempt_login()
    if not result["success"]:
        logger.error(f"Startup sign-in incomplete ({AUTH.state}): {result['message']}")


@mcp.tool()
def instagram_auth_status() -> Dict[str, Any]:
    """Report whether the server is signed in to Instagram, and what it needs if not.

    Call this first whenever another tool reports that the server is not signed in.

    Returns:
        A dictionary with the current auth state and the next step to take.
    """
    # With a seed configured the server mints its own 2FA code, so the caller
    # should just trigger a login rather than going to the user for a code that
    # is neither needed nor, for push-approval accounts, ever issued.
    # Only when the seed is the deciding factor. States like blocked or
    # unconfigured are not fixed by another login attempt — advising one there
    # would drive exactly the repeated failed logins the block exists to stop.
    if AUTH.totp_seed and not AUTH.authenticated and AUTH.state not in ("blocked", "unconfigured"):
        if AUTH.state == "bad_totp_seed":
            step = (
                "INSTAGRAM_TOTP_SEED is not a usable base32 secret, so the server cannot "
                "generate a code. This is a server configuration problem that no 2FA code "
                "from the user will fix. Spacing and case are handled automatically, so the "
                "value itself is wrong — most likely a backup code or recovery phrase was "
                "copied instead of the authenticator key Instagram shows when you set up "
                "an authenticator app."
            )
        elif AUTH.totp_rejected:
            step = (
                "Instagram rejected the code the server generated, so INSTAGRAM_TOTP_SEED is "
                "not this account's authenticator seed. Do not call instagram_login without a "
                "code — it regenerates the same rejected code. Ask the user for one live code "
                "to get in now, and tell them the server's seed needs correcting (or "
                "INSTAGRAM_SESSIONID set) so restarts work unattended."
            )
        else:
            step = (
                "Call instagram_login with no verification_code. A TOTP seed is configured, "
                "so the server generates the 2FA code itself — do not ask the user for one."
            )
        return {
            "authenticated": False,
            "state": AUTH.state,
            "username": AUTH.username,
            "detail": AUTH.detail,
            "totp_seed_configured": True,
            "session_file": str(AUTH.session_file) if AUTH.session_file else None,
            "next_step": step,
        }

    next_step = {
        "authenticated": "Nothing to do.",
        "needs_2fa": (
            "Ask the user for the current 6-digit 2FA code, then call instagram_login "
            "with verification_code set. An 8-digit backup code works too. If their 2FA "
            "is an approve-on-device push, Instagram issues no code at all — tell the user "
            "the server operator needs to set INSTAGRAM_SESSIONID (or INSTAGRAM_TOTP_SEED) "
            "in the server's own configuration. Never ask anyone to paste a session cookie "
            "to you; it is a password-equivalent credential and must not pass through here."
        ),
        "needs_login": "Call instagram_login to retry the sign-in.",
        "blocked": (
            "A previous sign-in failed in a way that needs a person. If it was 2FA, ask "
            "the user for a fresh code and call instagram_login with verification_code, or "
            "tell the user to set INSTAGRAM_SESSIONID on the server when the account "
            "approves logins by push instead of by code. Otherwise the credentials or "
            "account need attention."
        ),
        "unconfigured": (
            "The server has no credentials. Set INSTAGRAM_USERNAME and "
            "INSTAGRAM_PASSWORD, or run auth.py, then restart."
        ),
    }.get(AUTH.state, "Call instagram_login.")

    return {
        "authenticated": AUTH.authenticated,
        "state": AUTH.state,
        "username": AUTH.username,
        "detail": AUTH.detail,
        "totp_seed_configured": bool(AUTH.totp_seed),
        "session_file": str(AUTH.session_file) if AUTH.session_file else None,
        "next_step": next_step,
    }


@mcp.tool()
@rate_limited("login")
def instagram_login(
    verification_code: Optional[str] = None,
    force: bool = False,
) -> Dict[str, Any]:
    """Sign in to Instagram, optionally completing two-factor authentication.

    Credentials are read from the server's own configuration and are never passed
    in through this tool. Only the 2FA code, which the user reads off their phone,
    comes from the caller.

    Args:
        verification_code: The current 6-digit 2FA code, if Instagram asked for one.
            These expire in about 30 seconds, so send it as soon as the user gives it.
        force: Sign in again even when the server believes it is already signed in.
            Use when tools fail with authentication errors despite a healthy status —
            a restored session is trusted without proof, so it can be silently stale.
    Returns:
        A dictionary with success status, the resulting auth state, and a message.
    """
    if AUTH.authenticated and not verification_code and not force:
        return {
            "success": True,
            "state": AUTH.state,
            "message": (
                f"Already signed in as @{AUTH.username}. If Instagram tools are failing "
                f"with authentication errors anyway, call again with force=true to "
                f"replace a session that has gone stale."
            ),
        }

    code = (verification_code or "").strip()
    if code:
        # An operator supplying a code is the human step the block was waiting
        # for, so stop refusing before trying it.
        _clear_block()

    result = _attempt_login(verification_code=code)
    logger.info(f"instagram_login via tool -> {result['state']}")
    return result


@mcp.tool()
@rate_limited("dm_send")
def send_message(username: str, message: str) -> Dict[str, Any]:
    """Send an Instagram direct message to a user by username.

    Args:
        username: Instagram username of the recipient.
        message: The message text to send.
    Returns:
        A dictionary with success status and a status message.
    """
    if not username or not message:
        return {"success": False, "message": "Username and message must be provided."}
    try:
        user_id = client.user_id_from_username(username)
        if not user_id:
            return {"success": False, "message": f"User '{username}' not found."}
        dm = client.direct_send(message, [user_id])
        if dm:
            return {"success": True, "message": "Message sent to user.", "direct_message_id": getattr(dm, 'id', None)}
        else:
            return {"success": False, "message": "Failed to send message."}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("dm_send")
def reply_to_message(thread_id: str, message_id: str, message: str) -> Dict[str, Any]:
    """Send a quote reply to a specific message in an Instagram Direct Message thread.

    The reply renders in Instagram with the original message quoted above it, the same
    way a swipe-to-reply does in the app. Use list_chats to find the thread_id and
    list_messages to find the message_id you want to reply to.

    Args:
        thread_id: The thread ID containing the message being replied to.
        message_id: The ID of the message to quote.
        message: The reply text to send.
    Returns:
        A dictionary with success status and a status message.
    """
    if not thread_id or not message_id or not message:
        return {"success": False, "message": "thread_id, message_id and message must all be provided."}
    try:
        target = _find_message_in_thread(thread_id, message_id)
        if not target:
            return {
                "success": False,
                "message": f"Message '{message_id}' not found in the last 100 messages of thread '{thread_id}'.",
            }
        dm = client.direct_send(message, thread_ids=[int(thread_id)], reply_to_message=target)
        if dm:
            return {
                "success": True,
                "message": "Reply sent.",
                "direct_message_id": getattr(dm, 'id', None),
                "replied_to_message_id": message_id,
            }
        else:
            return {"success": False, "message": "Failed to send reply."}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("dm_send")
def send_photo_message(username: str, photo_path: str) -> Dict[str, Any]:
    """Send a photo via Instagram direct message to a user by username.

    Args:
        username: Instagram username of the recipient.
        photo_path: Path to the photo file to send.
        message: Optional message text to accompany the photo.
    Returns:
        A dictionary with success status and a status message.
    """
    if not username or not photo_path:
        return {"success": False, "message": "Username and photo_path must be provided."}
    
    if not os.path.exists(photo_path):
        return {"success": False, "message": f"Photo file not found: {photo_path}"}
    
    try:
        user_id = client.user_id_from_username(username)
        if not user_id:
            return {"success": False, "message": f"User '{username}' not found."}
        
        result = client.direct_send_photo(Path(photo_path), [user_id])
        if result:
            return {"success": True, "message": "Photo sent successfully.", "direct_message_id": getattr(result, 'id', None)}
        else:
            return {"success": False, "message": "Failed to send photo."}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("dm_send")
def send_video_message(username: str, video_path: str) -> Dict[str, Any]:
    """Send a video via Instagram direct message to a user by username.

    Args:
        username: Instagram username of the recipient.
        video_path: Path to the video file to send.
    Returns:
        A dictionary with success status and a status message.
    """
    if not username or not video_path:
        return {"success": False, "message": "Username and video_path must be provided."}
    
    if not os.path.exists(video_path):
        return {"success": False, "message": f"Video file not found: {video_path}"}
    
    try:
        user_id = client.user_id_from_username(username)
        if not user_id:
            return {"success": False, "message": f"User '{username}' not found."}

        result = client.direct_send_video(Path(video_path), [user_id])
        if result:
            return {"success": True, "message": "Video sent successfully.", "direct_message_id": getattr(result, 'id', None)}
        else:
            return {"success": False, "message": "Failed to send video."}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("lookup")
def list_chats(
    amount: int = 20,
    selected_filter: str = "",
    thread_message_limit: Optional[int] = None,
    full: bool = False,
    fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Get Instagram Direct Message threads (chats) from the user's account, with optional filters and limits.

    Args:
        amount: Number of threads to fetch (default 20).
        selected_filter: Filter for threads ("", "flagged", or "unread").
        thread_message_limit: Limit for messages per thread.
        full: If True, return the full thread object for each chat (default False).
        fields: If provided, return only these fields for each thread.
    Returns:
        A dictionary with success status and the list of threads or error message.
    """
    def thread_summary(thread):
        t = thread if isinstance(thread, dict) else thread.dict()
        users = t.get("users", [])
        user_summaries = [
            {
                "username": u.get("username"),
                "full_name": u.get("full_name"),
                "pk": u.get("pk")
            }
            for u in users
        ]
        return {
            "thread_id": t.get("id"),
            "thread_title": t.get("thread_title"),
            "users": user_summaries,
            "last_activity_at": t.get("last_activity_at"),
            "last_message": t.get("messages", [{}])[-1] if t.get("messages") else None
        }

    def filter_fields(thread, fields):
        t = thread if isinstance(thread, dict) else thread.dict()
        return {field: t.get(field) for field in fields}

    try:
        threads = client.direct_threads(amount, selected_filter, thread_message_limit)
        if full:
            return {"success": True, "threads": [t.dict() if hasattr(t, 'dict') else str(t) for t in threads]}
        elif fields:
            return {"success": True, "threads": [filter_fields(t, fields) for t in threads]}
        else:
            return {"success": True, "threads": [thread_summary(t) for t in threads]}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("lookup")
def list_messages(thread_id: str, amount: int = 20) -> Dict[str, Any]:
    """Get messages from a specific Instagram Direct Message thread by thread ID, with an optional limit.

    Args:
        thread_id: The thread ID to fetch messages from.
        amount: Number of messages to fetch (default 20).
    Returns:
        A dictionary with success status and the list of messages or error message.
    """
    if not thread_id:
        return {"success": False, "message": "Thread ID must be provided."}
    try:
        messages = client.direct_messages(thread_id, amount)
        result_msgs = []
        for m in messages:
            msg = m.dict() if hasattr(m, 'dict') else (m if isinstance(m, dict) else {})
            # Expose item_type and shared post/reel info if present
            item_type = getattr(m, 'item_type', None) or msg.get('item_type')
            shared_info = None
            shared_url = None
            shared_code = None
            if item_type in ["clip", "media_share", "reel_share", "xma_media_share", "post_share"]:
                # Try to extract code/url from known attributes
                clip = getattr(m, 'clip', None) or msg.get('clip')
                media_share = getattr(m, 'media_share', None) or msg.get('media_share')
                xma = getattr(m, 'xma_media_share', None) or msg.get('xma_media_share')
                post_share = getattr(m, 'post_share', None) or msg.get('post_share')
                # Try to get code/url from any of these
                for obj in [clip, media_share, xma, post_share]:
                    if obj:
                        shared_code = obj.get('code') or obj.get('pk')
                        shared_url = obj.get('url') or (f"https://www.instagram.com/reel/{shared_code}/" if shared_code else None)
                        shared_info = obj
                        break
            msg['item_type'] = item_type
            msg['shared_post_info'] = shared_info
            msg['shared_post_url'] = shared_url
            msg['shared_post_code'] = shared_code
            result_msgs.append(msg)
        return {"success": True, "messages": result_msgs}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("modify")
def mark_message_seen(thread_id: str, message_id: str) -> Dict[str, Any]:
    """Mark a message as seen in a direct message thread.

    Args:
        thread_id: The thread ID containing the message.
        message_id: The ID of the message to mark as seen.
    Returns:
        A dictionary with success status and a status message.
    """
    if not thread_id or not message_id:
        return {"success": False, "message": "Both thread_id and message_id must be provided."}
    
    try:
        result = client.direct_message_seen(int(thread_id), int(message_id))
        if result:
            return {"success": True, "message": "Message marked as seen."}
        else:
            return {"success": False, "message": "Failed to mark message as seen."}
    except Exception as e:
        return {"success": False, "message": str(e)}


def _reaction_context(thread_id: str, message_id: str) -> Dict[str, Any]:
    """Resolve the extra fields Instagram wants when reacting to a message.

    Reactions are accepted without these, but voice notes and disappearing media need
    target_item_type to attach correctly, so look the message up when we can and fall
    back to a bare reaction when we can't find it.
    """
    target = _find_message_in_thread(thread_id, message_id)
    if not target:
        return {}
    context: Dict[str, Any] = {"client_context": getattr(target, 'client_context', None)}
    item_type = getattr(target, 'item_type', None)
    if item_type in ("raven_media", "voice_media"):
        context["target_item_type"] = item_type
    return context


@mcp.tool()
@rate_limited("like")
def react_to_message(thread_id: str, message_id: str, emoji: str = "❤") -> Dict[str, Any]:
    """React to a message in an Instagram Direct Message thread with an emoji.

    Defaults to the heart reaction, which is what Instagram's double-tap "like" sends.

    Args:
        thread_id: The thread ID containing the message.
        message_id: The ID of the message to react to.
        emoji: The emoji to react with (default heart).
    Returns:
        A dictionary with success status and a status message.
    """
    if not thread_id or not message_id:
        return {"success": False, "message": "Both thread_id and message_id must be provided."}
    if not emoji:
        return {"success": False, "message": "Emoji must be provided."}
    try:
        result = client.direct_send_reaction(
            int(thread_id),
            int(message_id),
            emoji=emoji,
            **_reaction_context(thread_id, message_id),
        )
        if result:
            return {"success": True, "message": f"Reacted with {emoji}."}
        else:
            return {"success": False, "message": "Failed to react to message."}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("like")
def remove_message_reaction(thread_id: str, message_id: str, emoji: str = "❤") -> Dict[str, Any]:
    """Remove your own emoji reaction from a message in an Instagram Direct Message thread.

    The emoji must match the reaction you sent; it defaults to the heart reaction.

    Args:
        thread_id: The thread ID containing the message.
        message_id: The ID of the message to remove your reaction from.
        emoji: The emoji reaction to remove (default heart).
    Returns:
        A dictionary with success status and a status message.
    """
    if not thread_id or not message_id:
        return {"success": False, "message": "Both thread_id and message_id must be provided."}
    if not emoji:
        return {"success": False, "message": "Emoji must be provided."}
    try:
        result = client.direct_delete_reaction(
            int(thread_id),
            int(message_id),
            emoji=emoji,
            **_reaction_context(thread_id, message_id),
        )
        if result:
            return {"success": True, "message": f"Removed {emoji} reaction."}
        else:
            return {"success": False, "message": "Failed to remove reaction."}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("lookup")
def list_pending_chats(amount: int = 20) -> Dict[str, Any]:
    """Get Instagram Direct Message threads (chats) from the user's pending inbox.

    Args:
        amount: Number of pending threads to fetch (default 20).
    Returns:
        A dictionary with success status and the list of pending threads or error message.
    """
    try:
        threads = client.direct_pending_inbox(amount)
        return {"success": True, "threads": [t.dict() if hasattr(t, 'dict') else str(t) for t in threads]}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("search")
def search_threads(query: str) -> Dict[str, Any]:
    """Search Instagram Direct Message threads by username or keyword.

    Args:
        query: The search term (username or keyword).
    Returns:
        A dictionary with success status and the search results or error message.
    """
    if not query:
        return {"success": False, "message": "Query must be provided."}
    try:
        results = client.direct_search(query)
        return {"success": True, "results": [r.dict() if hasattr(r, 'dict') else str(r) for r in results]}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("lookup")
def get_thread_by_participants(user_ids: List[int]) -> Dict[str, Any]:
    """Get an Instagram Direct Message thread by participant user IDs.

    Args:
        user_ids: List of user IDs (ints).
    Returns:
        A dictionary with success status and the thread or error message.
    """
    if not user_ids or not isinstance(user_ids, list):
        return {"success": False, "message": "user_ids must be a non-empty list of user IDs."}
    try:
        thread = client.direct_thread_by_participants(user_ids)
        return {"success": True, "thread": thread.dict() if hasattr(thread, 'dict') else str(thread)}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("lookup")
def get_thread_details(thread_id: str, amount: int = 20) -> Dict[str, Any]:
    """Get details and messages for a specific Instagram Direct Message thread by thread ID, with an optional message limit.

    Args:
        thread_id: The thread ID to fetch details for.
        amount: Number of messages to fetch (default 20).
    Returns:
        A dictionary with success status and the thread details or error message.
    """
    if not thread_id:
        return {"success": False, "message": "Thread ID must be provided."}
    try:
        thread = client.direct_thread(thread_id, amount)
        return {"success": True, "thread": thread.dict() if hasattr(thread, 'dict') else str(thread)}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("lookup")
def get_user_id_from_username(username: str) -> Dict[str, Any]:
    """Get the Instagram user ID for a given username.

    Args:
        username: Instagram username.
    Returns:
        A dictionary with success status and the user ID or error message.
    """
    if not username:
        return {"success": False, "message": "Username must be provided."}
    try:
        user_id = client.user_id_from_username(username)
        if user_id:
            return {"success": True, "user_id": user_id}
        else:
            return {"success": False, "message": f"User '{username}' not found."}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("lookup")
def get_username_from_user_id(user_id: str) -> Dict[str, Any]:
    """Get the Instagram username for a given user ID.

    Args:
        user_id: Instagram user ID.
    Returns:
        A dictionary with success status and the username or error message.
    """
    if not user_id:
        return {"success": False, "message": "User ID must be provided."}
    try:
        username = client.username_from_user_id(user_id)
        if username:
            return {"success": True, "username": username}
        else:
            return {"success": False, "message": f"User ID '{user_id}' not found."}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("lookup")
def get_user_info(username: str) -> Dict[str, Any]:
    """Get detailed information about an Instagram user.

    Args:
        username: Instagram username to get information about.
    Returns:
        A dictionary with success status and user information.
    """
    if not username:
        return {"success": False, "message": "Username must be provided."}
    
    try:
        user = client.user_info_by_username(username)
        if user:
            user_data = {
                "user_id": str(user.pk),
                "username": user.username,
                "full_name": user.full_name,
                "biography": user.biography,
                "follower_count": user.follower_count,
                "following_count": user.following_count,
                "media_count": user.media_count,
                "is_private": user.is_private,
                "is_verified": user.is_verified,
                "profile_pic_url": str(user.profile_pic_url) if user.profile_pic_url else None,
                "external_url": str(user.external_url) if user.external_url else None,
                "category": user.category,
            }
            return {"success": True, "user_info": user_data}
        else:
            return {"success": False, "message": f"User '{username}' not found."}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("lookup")
def check_user_online_status(usernames: List[str]) -> Dict[str, Any]:
    """Check the online status of Instagram users.

    Args:
        usernames: List of Instagram usernames to check status for.
    Returns:
        A dictionary with success status and users' presence information.
    """
    if not usernames or not isinstance(usernames, list):
        return {"success": False, "message": "A list of usernames must be provided."}
    
    try:
        user_ids = []
        username_to_id = {}
        
        # Get user IDs for the usernames
        for username in usernames:
            try:
                user_id = client.user_id_from_username(username)
                if user_id:
                    user_ids.append(int(user_id))
                    username_to_id[user_id] = username
            except:
                continue
        
        if not user_ids:
            return {"success": False, "message": "No valid users found."}
        
        presence_data = client.direct_users_presence(user_ids)
        
        # Convert back to usernames
        result = {}
        for user_id_str, presence in presence_data.items():
            username = username_to_id.get(user_id_str, f"user_{user_id_str}")
            result[username] = presence
        
        return {"success": True, "presence_data": result}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("search")
def search_users(query: str) -> Dict[str, Any]:
    """Search for Instagram users by name or username.

    Args:
        query: Search term (name or username).
        count: Maximum number of users to return (default 10, max 50).
    Returns:
        A dictionary with success status and search results.
    """
    if not query:
        return {"success": False, "message": "Search query must be provided."}
    
    try:
        users = client.search_users(query)
        
        user_results = []
        for user in users:
            user_data = {
                "user_id": str(user.pk),
                "username": user.username,
                "full_name": user.full_name,
                "is_private": user.is_private,
                "profile_pic_url": str(user.profile_pic_url) if user.profile_pic_url else None,
                "follower_count": getattr(user, 'follower_count', None),
            }
            user_results.append(user_data)
        
        return {"success": True, "users": user_results, "count": len(user_results)}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("lookup")
def get_user_stories(username: str) -> Dict[str, Any]:
    """Get Instagram stories from a user.

    Args:
        username: Instagram username to get stories from.
    Returns:
        A dictionary with success status and stories information.
    """
    if not username:
        return {"success": False, "message": "Username must be provided."}
    
    try:
        user_id = client.user_id_from_username(username)
        if not user_id:
            return {"success": False, "message": f"User '{username}' not found."}
        
        stories = client.user_stories(user_id)
        
        story_results = []
        for story in stories:
            story_data = {
                "story_id": str(story.pk),
                "media_type": story.media_type,  # 1=photo, 2=video
                "taken_at": str(story.taken_at),
                "user": {
                    "username": story.user.username,
                    "full_name": story.user.full_name,
                    "user_id": str(story.user.pk)
                },
                "media_url": str(story.thumbnail_url) if story.thumbnail_url else None,
            }
            
            if story.media_type == 2 and story.video_url:
                story_data["video_url"] = str(story.video_url)
                story_data["video_duration"] = story.video_duration
            
            story_results.append(story_data)
        
        return {"success": True, "stories": story_results, "count": len(story_results)}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("like")
def like_media(media_url: str, like: bool = True) -> Dict[str, Any]:
    """Like or unlike an Instagram post.

    Args:
        media_url: URL of the Instagram post.
        like: True to like, False to unlike the post.
    Returns:
        A dictionary with success status and a status message.
    """
    if not media_url:
        return {"success": False, "message": "Media URL must be provided."}
    
    try:
        media_pk = client.media_pk_from_url(media_url)
        if not media_pk:
            return {"success": False, "message": "Invalid media URL or post not found."}
        
        if like:
            result = client.media_like(media_pk)
            action = "liked"
        else:
            result = client.media_unlike(media_pk)
            action = "unliked"
        
        if result:
            return {"success": True, "message": f"Post {action} successfully."}
        else:
            return {"success": False, "message": f"Failed to {action.rstrip('d')} post."}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("lookup")
def get_user_followers(username: str, count: int = 20) -> Dict[str, Any]:
    """Get followers of an Instagram user.

    Args:
        username: Instagram username to get followers for.
        count: Maximum number of followers to return (default 20).
    Returns:
        A dictionary with success status and followers list.
    """
    if not username:
        return {"success": False, "message": "Username must be provided."}
    
    try:
        user_id = client.user_id_from_username(username)
        if not user_id:
            return {"success": False, "message": f"User '{username}' not found."}
        
        followers = client.user_followers(user_id, amount=count)
        
        follower_results = []
        for follower_id, follower in followers.items():
            follower_data = {
                "user_id": str(follower.pk),
                "username": follower.username,
                "full_name": follower.full_name,
                "is_private": follower.is_private,
                "profile_pic_url": str(follower.profile_pic_url) if follower.profile_pic_url else None,
            }
            follower_results.append(follower_data)
        
        return {"success": True, "followers": follower_results, "count": len(follower_results)}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("lookup")
def get_user_following(username: str, count: int = 20) -> Dict[str, Any]:
    """Get users that an Instagram user is following.

    Args:
        username: Instagram username to get following list for.
        count: Maximum number of following to return (default 20).
    Returns:
        A dictionary with success status and following list.
    """
    if not username:
        return {"success": False, "message": "Username must be provided."}
    
    try:
        user_id = client.user_id_from_username(username)
        if not user_id:
            return {"success": False, "message": f"User '{username}' not found."}
        
        following = client.user_following(user_id, amount=count)
        
        following_results = []
        for following_id, followed_user in following.items():
            following_data = {
                "user_id": str(followed_user.pk),
                "username": followed_user.username,
                "full_name": followed_user.full_name,
                "is_private": followed_user.is_private,
                "profile_pic_url": str(followed_user.profile_pic_url) if followed_user.profile_pic_url else None,
            }
            following_results.append(following_data)
        
        return {"success": True, "following": following_results, "count": len(following_results)}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("lookup")
def get_user_posts(username: str, count: int = 12) -> Dict[str, Any]:
    """Get recent posts from an Instagram user.

    Args:
        username: Instagram username to get posts from.
        count: Maximum number of posts to return (default 12).
    Returns:
        A dictionary with success status and posts list.
    """
    if not username:
        return {"success": False, "message": "Username must be provided."}
    
    try:
        user_id = client.user_id_from_username(username)
        if not user_id:
            return {"success": False, "message": f"User '{username}' not found."}
        
        medias = client.user_medias(user_id, amount=count)
        
        media_results = []
        for media in medias:
            media_data = {
                "media_id": str(media.pk),
                "media_type": media.media_type,  # 1=photo, 2=video, 8=album
                "caption": media.caption_text if media.caption_text else "",
                "like_count": media.like_count,
                "comment_count": media.comment_count,
                "taken_at": str(media.taken_at),
                "media_url": str(media.thumbnail_url) if media.thumbnail_url else None,
            }
            
            if media.media_type == 2 and media.video_url:
                media_data["video_url"] = str(media.video_url)
                media_data["video_duration"] = media.video_duration
            
            media_results.append(media_data)
        
        return {"success": True, "posts": media_results, "count": len(media_results)}
    except Exception as e:
        return {"success": False, "message": str(e)}


# Downloads land in the user data dir next to the sessions, so the server does
# not depend on its working directory being writable - under Docker the cwd is
# owned by root and "./downloads" fails with EACCES.
DEFAULT_DOWNLOAD_DIR = Path.home() / ".instagram_dm_mcp" / "downloads"


def _resolve_download_directory(download_path: str) -> str:
    """Resolve the download directory, creating it, and default it when unset."""
    directory = Path(download_path).expanduser() if download_path else DEFAULT_DOWNLOAD_DIR
    directory.mkdir(parents=True, exist_ok=True)
    return str(directory)


def _direct_media_kind(media) -> str:
    """Label a direct message attachment as photo, video or voice."""
    if getattr(media, 'video_url', None):
        return "video"
    if getattr(media, 'audio_url', None):
        return "voice"
    return "photo"


def _download_single_media(media, download_path: str) -> str:
    """Download a single media item and return the file path.

    Attachments on a direct message are DirectMedia, which carries its own CDN
    urls and has no pk - it is not feed media, so photo_download/video_download
    cannot resolve it. Download those by url, and keep the pk path for the feed
    Media that the shared-post tools hand over.
    """
    media_pk = getattr(media, 'pk', None)
    media_type = getattr(media, 'media_type', None)
    if media_pk:
        if media_type == 1:  # Photo
            return str(client.photo_download(media_pk, download_path))
        elif media_type == 2:  # Video
            return str(client.video_download(media_pk, download_path))
        else:
            raise ValueError(f"Unsupported media type: {media_type}")

    # Name by the message-scoped media id so repeat downloads overwrite in place
    # rather than piling up CDN hashes.
    filename = f"direct_{getattr(media, 'id', None) or 'media'}"
    source_url = (
        getattr(media, 'video_url', None)
        or getattr(media, 'audio_url', None)
        or getattr(media, 'thumbnail_url', None)
    )
    if not source_url:
        raise ValueError(f"Message media has no downloadable url (media type: {media_type})")
    if _direct_media_kind(media) == "photo":
        return str(client.photo_download_by_url(str(source_url), filename, download_path))
    return str(client.video_download_by_url(str(source_url), filename, download_path))


def _find_message_in_thread(thread_id: str, message_id: str):
    """Find a specific message in a thread."""
    messages = client.direct_messages(thread_id, 100)
    return next((m for m in messages if str(m.id) == message_id), None)


@mcp.tool()
@rate_limited("lookup")
def list_media_messages(thread_id: str, limit: int = 100) -> Dict[str, Any]:
    """List all messages containing media in an Instagram direct message thread.
    Args:
        thread_id: The ID of the thread to check for media messages
        limit: Maximum number of messages to check (default 100, max 200)
    Returns:
        A dictionary containing success status and list of all media messages found
    """
    try:
        limit = min(limit, 200)
        messages = client.direct_messages(thread_id, limit)
        media_messages = []
        for message in messages:
            if message.media:
                media_messages.append({
                    "message_id": str(message.id),
                    "media_type": _direct_media_kind(message.media),
                    "timestamp": str(message.timestamp) if hasattr(message, 'timestamp') else None,
                    "sender_user_id": message.user_id if hasattr(message, 'user_id') else None
                })
        return {
            "success": True,
            "message": f"Found {len(media_messages)} messages with media",
            "total_messages_checked": len(messages),
            "media_messages": media_messages
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to list media messages: {str(e)}"
        }

@mcp.tool()
@rate_limited("lookup")
def download_media_from_message(message_id: str, thread_id: str, download_path: str = "") -> Dict[str, Any]:
    """Download media from a specific Instagram direct message and get the local file path.
    Args:
        message_id: The ID of the message containing the media
        thread_id: The ID of the thread containing the message
        download_path: Directory to save the downloaded file (default: ~/.instagram_dm_mcp/downloads)
    Returns:
        A dictionary containing success status, a status message, and the file path if successful
    """
    try:
        download_path = _resolve_download_directory(download_path)
        target_message = _find_message_in_thread(thread_id, message_id)
        if not target_message:
            return {
                "success": False,
                "message": f"Message {message_id} not found in thread {thread_id}"
            }
        if not target_message.media:
            return {
                "success": False,
                "message": "This message does not contain media"
            }
        file_path = _download_single_media(target_message.media, download_path)
        return {
            "success": True,
            "message": "Media downloaded successfully",
            "file_path": file_path,
            "media_type": _direct_media_kind(target_message.media),
            "message_id": message_id,
            "thread_id": thread_id
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to download media: {str(e)}"
        }


@mcp.tool()
@rate_limited("lookup")
def download_shared_post_from_message(message_id: str, thread_id: str, download_path: str = "") -> Dict[str, Any]:
    """Download media from a shared post/reel/clip in a DM message and get the local file path.
    Args:
        message_id: The ID of the message containing the shared post/reel/clip
        thread_id: The ID of the thread containing the message
        download_path: Directory to save the downloaded file (default: ~/.instagram_dm_mcp/downloads)
    Returns:
        A dictionary containing success status, a status message, and the file path if successful
    """
    try:
        download_path = _resolve_download_directory(download_path)
        target_message = _find_message_in_thread(thread_id, message_id)
        if not target_message:
            return {"success": False, "message": f"Message {message_id} not found in thread {thread_id}"}
        item_type = getattr(target_message, 'item_type', None)
        # Extract shared post/reel/clip URL
        shared_url = None
        shared_code = None
        shared_obj = None
        if item_type in ["clip", "media_share", "reel_share", "xma_media_share", "post_share"]:
            for attr in ['clip', 'media_share', 'xma_media_share', 'post_share']:
                obj = getattr(target_message, attr, None)
                if obj:
                    shared_code = obj.get('code') or obj.get('pk')
                    shared_url = obj.get('url') or (f"https://www.instagram.com/reel/{shared_code}/" if shared_code else None)
                    shared_obj = obj
                    break
        if not shared_url:
            return {"success": False, "message": "This message does not contain a supported shared post/reel/clip"}
        # Download using Instagrapi
        try:
            media_pk = client.media_pk_from_url(shared_url)
            media = client.media_info(media_pk)
            if media.media_type == 1:
                file_path = str(client.photo_download(media_pk, download_path))
                media_type = "photo"
            elif media.media_type == 2:
                file_path = str(client.video_download(media_pk, download_path))
                media_type = "video"
            elif media.media_type == 8:  # album
                # Download all items in album
                album_paths = client.album_download(media_pk, download_path)
                file_path = str(album_paths)
                media_type = "album"
            else:
                return {"success": False, "message": f"Unsupported media type: {media.media_type}"}
            return {
                "success": True,
                "message": "Shared post/reel/clip downloaded successfully",
                "file_path": file_path,
                "media_type": media_type,
                "shared_post_url": shared_url,
                "message_id": message_id,
                "thread_id": thread_id
            }
        except Exception as e:
            return {"success": False, "message": f"Failed to download shared post/reel/clip: {str(e)}"}
    except Exception as e:
        return {"success": False, "message": f"Failed to process message: {str(e)}"}


@mcp.tool()
@rate_limited("modify")
def delete_message(thread_id: str, message_id: str) -> Dict[str, Any]:
    """Delete a message from a direct message thread.

    Args:
        thread_id: The thread ID containing the message.
        message_id: The ID of the message to delete.
    Returns:
        A dictionary with success status and a status message.
    """
    if not thread_id or not message_id:
        return {"success": False, "message": "Both thread_id and message_id must be provided."}
    
    try:
        result = client.direct_message_delete(int(thread_id), int(message_id))
        if result:
            return {"success": True, "message": "Message deleted successfully."}
        else:
            return {"success": False, "message": "Failed to delete message."}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("modify")
def hide_chat(thread_id: str, move_to_spam: bool = False) -> Dict[str, Any]:
    """Remove a direct message conversation from the inbox.

    This is what Instagram's own "Delete" on a chat does: the thread is hidden
    from your inbox, not erased for the other person, and it reappears if they
    send another message.

    Args:
        thread_id: The thread ID to remove from the inbox.
        move_to_spam: True to file it under hidden requests (spam) instead of
            simply hiding it. Defaults to False.
    Returns:
        A dictionary with success status and a status message.
    """
    if not thread_id:
        return {"success": False, "message": "thread_id must be provided."}

    try:
        thread_id_int = int(thread_id)
    except (TypeError, ValueError):
        return {"success": False, "message": f"thread_id must be numeric, got {thread_id!r}."}

    try:
        result = client.direct_thread_hide(thread_id_int, move_to_spam=move_to_spam)
        if result:
            where = "moved to hidden requests (spam)" if move_to_spam else "hidden from the inbox"
            return {
                "success": True,
                "message": f"Chat {where}. It returns to the inbox if they message again.",
                "thread_id": thread_id,
                "moved_to_spam": move_to_spam,
            }
        return {"success": False, "message": "Instagram did not confirm hiding the chat."}
    except Exception as e:
        return {"success": False, "message": str(e)}


@mcp.tool()
@rate_limited("modify")
def mute_conversation(thread_id: str, mute: bool = True) -> Dict[str, Any]:
    """Mute or unmute a direct message conversation.

    Args:
        thread_id: The thread ID to mute/unmute.
        mute: True to mute, False to unmute the conversation.
    Returns:
        A dictionary with success status and a status message.
    """
    if not thread_id:
        return {"success": False, "message": "Thread ID must be provided."}
    
    try:
        if mute:
            result = client.direct_thread_mute(int(thread_id))
            action = "muted"
        else:
            result = client.direct_thread_unmute(int(thread_id))
            action = "unmuted"
        
        if result:
            return {"success": True, "message": f"Conversation {action} successfully."}
        else:
            return {"success": False, "message": f"Failed to {action.rstrip('d')} conversation."}
    except Exception as e:
        return {"success": False, "message": str(e)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", type=str, help="Instagram username (also via INSTAGRAM_USERNAME env)")
    parser.add_argument("--password", type=str, help="Instagram password (also via INSTAGRAM_PASSWORD env)")
    parser.add_argument(
        "--transport",
        type=str,
        choices=["stdio", "streamable-http", "sse"],
        default=os.getenv("MCP_TRANSPORT", "stdio"),
        help="MCP transport to serve on (also via MCP_TRANSPORT env). Default: stdio",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=os.getenv("MCP_HOST", "127.0.0.1"),
        help="Bind address for HTTP transports (also via MCP_HOST env). Default: 127.0.0.1",
    )
    # Resolved before the parser is built, so a bad value reports itself rather
    # than raising ValueError out of the default expression as a bare traceback.
    _env_port = (os.getenv("MCP_PORT") or "").strip()
    try:
        _default_port = int(_env_port) if _env_port else 8000
    except ValueError:
        print(f"Error: MCP_PORT is not a number ({_env_port!r})", file=sys.stderr)
        exit(1)

    parser.add_argument(
        "--port",
        type=int,
        default=_default_port,
        help="Bind port for HTTP transports (also via MCP_PORT env). Default: 8000",
    )
    parser.add_argument(
        "--path",
        type=str,
        default=os.getenv("MCP_PATH"),
        help="HTTP path the MCP endpoint is mounted at (also via MCP_PATH env). Default: /mcp for streamable-http, /sse for sse",
    )
    args = parser.parse_args()

    MCP_ENDPOINT = args.path or ("/sse" if args.transport == "sse" else "/mcp")

    # Resolve username: CLI arg > env var > current_user.txt written by auth.py
    # Session files live in the user data dir (per OS user, isolated from
    # any project checkout). This makes the server account-agnostic: every
    # OpenSwarm user on every machine resolves the same canonical path
    # regardless of where mcp_server.py is spawned from.
    SESSION_DIR = Path.home() / ".instagram_dm_mcp" / "sessions"
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    CURRENT_USER_FILE = SESSION_DIR / "current_user.txt"

    # One-shot migration: prior versions wrote these to the repo root. If
    # an old current_user.txt is still there and the new location is empty,
    # carry it over so existing setups keep working without a re-sign-in.
    _LEGACY_ROOT = Path(__file__).parent.parent
    _legacy_user_file = _LEGACY_ROOT / "current_user.txt"
    if _legacy_user_file.exists() and not CURRENT_USER_FILE.exists():
        try:
            CURRENT_USER_FILE.write_text(_legacy_user_file.read_text())
            logger.info(f"Migrated current_user.txt to {CURRENT_USER_FILE}")
        except Exception:
            pass

    username = args.username or os.getenv("INSTAGRAM_USERNAME")
    if not username and CURRENT_USER_FILE.exists():
        username = CURRENT_USER_FILE.read_text().strip() or None

    if username:
        SESSION_FILE = SESSION_DIR / f"{username}_session.json"
        _legacy_session = _LEGACY_ROOT / f"{username}_session.json"
        if _legacy_session.exists() and not SESSION_FILE.exists():
            try:
                SESSION_FILE.write_bytes(_legacy_session.read_bytes())
                logger.info(f"Migrated {username} session to {SESSION_FILE}")
            except Exception:
                pass
    else:
        SESSION_FILE = None
        logger.error("No username configured and no current_user.txt found.")

    AUTH.username = username
    AUTH.password = args.password or os.getenv("INSTAGRAM_PASSWORD")
    # Instagram shows the TOTP seed in spaced groups of four, and base32 accepts
    # neither spaces nor a lowercase-only reading, so a verbatim copy/paste is
    # unusable as-is. Normalise rather than make everyone notice that.
    # Strip only the separators Instagram's own display uses. Deleting every
    # non-base32 character instead would quietly turn a malformed secret (one
    # containing 0, 1, 8 or 9) into a valid-looking one that mints wrong codes
    # forever; leaving those in means it fails loudly as bad_totp_seed, which
    # is the accurate diagnosis.
    _raw_seed = os.getenv("INSTAGRAM_TOTP_SEED") or ""
    AUTH.totp_seed = re.sub(r"[\s\-_]", "", _raw_seed).upper() or None
    if _raw_seed and AUTH.totp_seed != _raw_seed.strip():
        logger.info("Normalised INSTAGRAM_TOTP_SEED (stripped separators, uppercased)")
    _raw_sessionid = os.getenv("INSTAGRAM_SESSIONID") or ""
    AUTH.sessionid = unquote(_raw_sessionid.strip().strip('"')) or None
    AUTH.session_dir = SESSION_DIR
    AUTH.session_file = SESSION_FILE

    # Sign-in is attempted once here and never retried on a loop: if it cannot
    # complete, the server still starts and reports what it needs through the
    # instagram_auth_status / instagram_login tools.
    bootstrap_auth()
    if AUTH.authenticated:
        logger.info(f"Successfully authenticated to Instagram ({AUTH.detail})")
    else:
        logger.warning(
            f"Starting without a usable Instagram session (state: {AUTH.state}). "
            f"Instagram tools will refuse until you sign in via the instagram_login tool."
        )

    try:
        if args.transport == "stdio":
            logger.info("Serving MCP over stdio")
            # The startup banner would go to stdout and corrupt the JSON-RPC stream.
            mcp.run(transport="stdio", show_banner=False)
        else:
            logger.info(f"Serving MCP over {args.transport} at http://{args.host}:{args.port}{MCP_ENDPOINT}")
            mcp.run(
                transport=args.transport,
                host=args.host,
                port=args.port,
                path=MCP_ENDPOINT,
            )
    except Exception as e:
        logger.error(f"MCP server stopped with an error: {e}")
        print(f"Error: MCP server stopped - {e}", file=sys.stderr)
        exit(1)
