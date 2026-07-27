from __future__ import annotations

import os
import sys
import threading
import time
import webbrowser

import uvicorn

from app.main import app as fastapi_app

HOST = os.environ.get("NAS_HOST", "127.0.0.1")
PORT = int(os.environ.get("NAS_PORT", "8000"))


def _open_browser_when_ready(host: str, port: int) -> None:
    if os.environ.get("NAS_NO_BROWSER"):
        return
    time.sleep(1.2)  # Give uvicorn a moment to finish binding the port.
    try:
        webbrowser.open(f"http://{host}:{port}")
    except Exception:
        pass  # A browser-launch failure should never take the server down with it.


def main() -> None:
    threading.Thread(target=_open_browser_when_ready, args=(HOST, PORT), daemon=True).start()
    # Passing the app object directly (rather than the "app.main:app" string form)
    # is required for this to work when frozen: PyInstaller's static analysis
    # only sees literal import statements, not strings resolved at runtime, so a
    # string target silently drops the whole app package from the bundle.
    uvicorn.run(fastapi_app, host=HOST, port=PORT, reload=False, use_colors=False)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"\nNetwork Automation Studio failed to start: {exc}\n", file=sys.stderr)
        if getattr(sys, "frozen", False):
            # A double-clicked .exe's console window closes the instant the
            # process exits, so pause here long enough to actually read the error.
            input("Press Enter to close this window...")
        raise
