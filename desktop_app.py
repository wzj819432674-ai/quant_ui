from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

try:
    from PySide6.QtCore import QUrl
    from PySide6.QtWebEngineWidgets import QWebEngineView
    from PySide6.QtWidgets import QApplication, QMainWindow
except ImportError as exc:
    raise SystemExit(
        "Missing dependency: PySide6. Install with: py -m pip install PySide6"
    ) from exc


def wait_for_url(url: str, timeout_seconds: int = 30) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=1):
                return True
        except URLError:
            time.sleep(0.25)
        except Exception:
            time.sleep(0.25)
    return False


def stop_process(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def start_streamlit(app_file: Path, host: str, port: int) -> subprocess.Popen:
    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_file),
        "--server.headless=true",
        f"--server.address={host}",
        f"--server.port={port}",
        "--browser.gatherUsageStats=false",
    ]

    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    return subprocess.Popen(
        command,
        cwd=str(app_file.parent),
        creationflags=creationflags,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


class BrowserWindow(QMainWindow):
    def __init__(self, title: str, url: str, width: int, height: int):
        super().__init__()
        self.setWindowTitle(title)
        self.resize(width, height)
        browser = QWebEngineView(self)
        browser.setUrl(QUrl(url))
        self.setCentralWidget(browser)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Desktop wrapper that shows your web app in a native window."
    )
    parser.add_argument(
        "--url",
        default="",
        help="Open this URL directly. If omitted, starts Streamlit from --app-file.",
    )
    parser.add_argument(
        "--app-file",
        default="app.py",
        help="Streamlit app file to launch when --url is not provided.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host for Streamlit server.")
    parser.add_argument("--port", type=int, default=8501, help="Port for Streamlit server.")
    parser.add_argument("--title", default="Quant UI", help="Desktop window title.")
    parser.add_argument("--width", type=int, default=1400, help="Window width in pixels.")
    parser.add_argument("--height", type=int, default=900, help="Window height in pixels.")
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Seconds to wait for Streamlit startup.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    process: subprocess.Popen | None = None

    if args.url:
        target_url = args.url
    else:
        app_file = (Path.cwd() / args.app_file).resolve()
        if not app_file.exists():
            raise SystemExit(f"Streamlit app file not found: {app_file}")

        target_url = f"http://{args.host}:{args.port}"
        process = start_streamlit(app_file, args.host, args.port)
        if not wait_for_url(target_url, timeout_seconds=args.timeout):
            stop_process(process)
            raise SystemExit(
                f"Streamlit did not start within {args.timeout}s at {target_url}."
            )

    qt_app = QApplication(sys.argv)
    window = BrowserWindow(args.title, target_url, args.width, args.height)
    window.show()
    try:
        exit_code = qt_app.exec()
    finally:
        stop_process(process)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
