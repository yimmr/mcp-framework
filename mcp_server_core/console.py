"""Console and logging utilities for cross-platform execution."""
from __future__ import annotations

import sys

_CONSOLE_RECONFIGURED = False


def configure_console_encoding() -> None:
    """Ensure standard output and error streams use UTF-8 on Windows without redundant calls."""
    global _CONSOLE_RECONFIGURED
    if _CONSOLE_RECONFIGURED:
        return
    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    _CONSOLE_RECONFIGURED = True


# Run once upon import
configure_console_encoding()
