# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""One quiet attempt to import `cryptography`, shared by signing and e2e.

A broken install (a system python3-cryptography whose _cffi_backend is missing) makes pyo3 print a Python
traceback and a Rust panic to stderr before the import fails, even for `airc --help`. The import is tried
once, with stderr sent to a temporary file; the result is cached, and what was printed is kept for -v."""

from __future__ import annotations

import os
import sys
import tempfile

_state: dict = {}

HINT = ("the Python package 'cryptography' is missing or broken: pip install cryptography "
        "(Debian/Ubuntu: apt install python3-cryptography; if that import fails, "
        "python3 -m venv v && v/bin/pip install cryptography, then run airc with v/bin/python3)")


def available() -> bool:
    """True when cryptography imports; tried once, quietly."""
    if "ok" in _state:
        return _state["ok"]
    saved, cap = None, None
    try:
        sys.stderr.flush()
        saved, cap = os.dup(2), tempfile.TemporaryFile()
        os.dup2(cap.fileno(), 2)
    except (OSError, ValueError, AttributeError):   # no real fd 2 (embedded, tests): import unguarded
        saved = None
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519  # noqa: F401
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: F401
        _state["ok"] = True
    except BaseException as e:                   # pyo3's PanicException derives from BaseException
        if isinstance(e, (KeyboardInterrupt, SystemExit)):
            raise
        _state["ok"] = False
        _state["error"] = f"{e.__class__.__name__}: {e}"
    finally:
        if saved is not None:
            sys.stderr.flush()
            os.dup2(saved, 2); os.close(saved)
            cap.seek(0); _state["stderr"] = cap.read().decode(errors="replace"); cap.close()
    return _state["ok"]


def detail() -> str:
    """What the failed import said (for -v)."""
    return (_state.get("error", "") + "\n" + _state.get("stderr", "")).strip()
