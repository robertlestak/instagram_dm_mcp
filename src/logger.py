"""Central logging setup.

Each module here does its own `logging.getLogger(__name__)` and none of them
attached a handler, so every record fell through to logging's last-resort
handler: WARNING and above, no timestamp, everything below dropped on the
floor. That is why an auth path which carefully logs each step at INFO left
nothing in `kubectl logs` to diagnose a dead session from — the lines were
written, but nowhere they could be read.

Configure the root logger once, here, and let each module's own logger inherit
it. The root stays at WARNING so third-party chatter (urllib3, httpx,
instagrapi's request log) does not drown the signal; only this project's
loggers are turned up.
"""

import logging
import os
import sys

_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Module logger names belonging to this project. mcp_server.py is executed as a
# script, so its records arrive under "__main__" rather than its filename.
_OWN_LOGGERS = ("__main__", "mcp_server", "rate_limiter", "logger", "auth")

_HANDLER_MARK = "_instagram_dm_mcp_handler"


def configure_logging() -> None:
    """Attach a formatted stderr handler to the root logger, at most once."""
    root = logging.getLogger()
    if not any(getattr(h, _HANDLER_MARK, False) for h in root.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        setattr(handler, _HANDLER_MARK, True)
        root.addHandler(handler)

    root.setLevel(logging.WARNING)
    for name in _OWN_LOGGERS:
        logging.getLogger(name).setLevel(_LEVEL)


configure_logging()

# Kept for anything that imports this module's logger directly.
logger = logging.getLogger(__name__)
