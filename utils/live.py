#!/usr/bin/env python3
"""
Live single-line "currently testing" display.

Writes the payload being tested to one rewriting line (\r) so the user sees
progress without flooding the terminal. Findings are still printed normally:
enable() monkey-patches builtins.print so every real print() first wipes the
live line, keeping findings on their own clean line.

No-op when stdout is not a TTY (piped / redirected to a file), so logs stay clean.
"""
import builtins
import shutil
import sys

_orig_print = builtins.print
_active = False
_enabled = False


def _clear() -> None:
    global _active
    if _active:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
        _active = False


def _patched_print(*args, **kwargs):
    _clear()
    _orig_print(*args, **kwargs)


def enable() -> None:
    """Route all print() through the live-line-aware wrapper."""
    global _enabled
    if _enabled:
        return
    builtins.print = _patched_print
    _enabled = True


def testing(label) -> None:
    """Show `label` on the live line (truncated to terminal width)."""
    global _active
    if not sys.stdout.isatty():
        return
    label = str(label).replace("\n", " ").replace("\r", " ")
    width = shutil.get_terminal_size((80, 20)).columns
    line = f"      \033[90m→ testing: {label}\033[0m"
    # account for the escape codes not taking visible space
    visible_budget = width - 1 + len("\033[90m\033[0m")
    if len(line) > visible_budget:
        line = line[:visible_budget - 1] + "…"
    sys.stdout.write("\r\033[K" + line)
    sys.stdout.flush()
    _active = True


def clear() -> None:
    """Wipe the live line (call before a block of normal output)."""
    _clear()
