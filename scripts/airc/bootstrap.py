# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Make `cryptography` available to ./airc and ./aircd run from the unpacked tarball.

Signing (everything over HTTPS) and encryption need the `cryptography` package, and a missing or broken
copy is the most common first-run failure. If this interpreter cannot import it, the launcher uses a
private virtual environment at ~/.airc/venv that has it, creating it the first time with pip (it says
so first). AIRC_NO_BOOTSTRAP=1 turns this off. If it cannot be done (no network, no venv module), it
prints one warning with what to install and carries on: commands that need no signing still work.
An install made with pip, pipx or uv (pyproject.toml) already has cryptography and never gets here."""

from __future__ import annotations

import os
import subprocess
import sys

VENV = os.path.expanduser(os.environ.get("AIRC_VENV", "~/.airc/venv"))

from . import __version__

INSTALL = (f"install it with one of:  pipx install https://airc.dev/docs/download/airc-{__version__}.tar.gz  |  "
           "python3 -m pip install --user cryptography  |  apt install python3-cryptography  |  "
           "python3 -m venv ~/.airc/venv && ~/.airc/venv/bin/pip install cryptography")


def _venv_python() -> str:
    return os.path.join(VENV, "bin", "python3")


def _has_crypto(python: str) -> bool:
    try:
        return subprocess.run([python, "-c", "import cryptography.hazmat.primitives.asymmetric.ed25519"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _warn(why: str) -> None:
    print(f"airc: warning: the Python package 'cryptography' is missing or broken ({why}); signing (anything over "
          f"HTTPS) and encryption will not work. {INSTALL}", file=sys.stderr)


def ensure(script: str) -> None:
    """Called by the launchers before anything else. Returns if this interpreter can go on; otherwise
    re-executes the launcher under ~/.airc/venv's python and does not return."""
    from . import cryptolib
    if cryptolib.available() or os.environ.get("AIRC_BOOTSTRAPPED"):
        return
    if os.environ.get("AIRC_NO_BOOTSTRAP"):
        _warn("AIRC_NO_BOOTSTRAP is set, so it was not installed")
        return
    py = _venv_python()
    if not (os.path.exists(py) and _has_crypto(py)):
        print(f"airc: the Python package 'cryptography' is missing or broken here; installing it into {VENV} "
              f"(once; AIRC_NO_BOOTSTRAP=1 skips this) ...", file=sys.stderr)
        try:
            if not os.path.exists(py):
                subprocess.run([sys.executable, "-m", "venv", VENV], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300)
            r = subprocess.run([py, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "cryptography"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=600)
            if r.returncode != 0:
                last = (r.stderr or b"").decode(errors="replace").strip().splitlines()
                raise RuntimeError(last[-1] if last else f"pip exited {r.returncode}")
        except subprocess.CalledProcessError as e:
            err = (e.stderr or b"").decode(errors="replace").strip().splitlines()
            _warn("could not create a virtual environment: " + (err[-1] if err else str(e)) +
                  " (Debian/Ubuntu: apt install python3-venv)")
            return
        except (OSError, subprocess.SubprocessError, RuntimeError) as e:
            _warn(f"could not install it: {e}")
            return
        if not _has_crypto(py):
            _warn(f"installed into {VENV}, but it still does not import")
            return
        print("airc: done.", file=sys.stderr)
    os.environ["AIRC_BOOTSTRAPPED"] = "1"
    os.execv(py, [py, script] + sys.argv[1:])
