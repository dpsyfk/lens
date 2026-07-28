#!/usr/bin/env python3
"""Exercise a packaged Lens binary through a real local HTTP proxy flow."""

from __future__ import annotations

import argparse
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time


TIMEOUT_SECONDS = 20
SECRET = "lens-dogfood-secret"


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        body = b"lens-dogfood-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    return parser.parse_args()


def free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def run_metadata_checks(binary: Path) -> None:
    commands = (
        ([str(binary), "--version"], "lens "),
        ([str(binary), "quickstart"], "lens doctor"),
        ([str(binary), "doctor", "--check", "config"], "lens doctor"),
    )
    for command, expected in commands:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
        if expected not in result.stdout:
            raise RuntimeError(f"{command!r} did not report {expected!r}")


def wait_for_listener(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise RuntimeError(
                f"Lens exited before listening ({process.returncode})\n{stdout}\n{stderr}"
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"Lens did not listen on 127.0.0.1:{port}")


def proxy_request(proxy_port: int, upstream_port: int) -> bytes:
    request = (
        f"GET http://127.0.0.1:{upstream_port}/dogfood?token={SECRET} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{upstream_port}\r\n"
        f"Authorization: Bearer {SECRET}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    chunks: list[bytes] = []
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as client:
        client.sendall(request)
        client.settimeout(5)
        while True:
            chunk = client.recv(64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def stop_process(process: subprocess.Popen[str]) -> tuple[str, str, bool]:
    graceful = os.name != "nt"
    if graceful:
        os.killpg(process.pid, signal.SIGINT)
    else:
        # Windows CI cannot safely direct CTRL_C_EVENT to a detached child from
        # every runner shell. Forwarding is still tested there; Unix runners
        # additionally verify graceful shutdown and the final redacted export.
        process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        raise RuntimeError("Lens did not stop within the smoke-test deadline")
    if graceful and process.returncode != 0:
        raise RuntimeError(
            f"Lens graceful shutdown failed ({process.returncode})\n{stdout}\n{stderr}"
        )
    return stdout, stderr, graceful


def verify_export(path: Path) -> None:
    contents = path.read_text(encoding="utf-8")
    if SECRET in contents:
        raise RuntimeError("release smoke export retained a configured secret")
    records = [json.loads(line) for line in contents.splitlines() if line.strip()]
    if not any(record.get("protocol") == "http1" for record in records):
        raise RuntimeError("release smoke export contains no decoded HTTP/1 flow")
    if not any(record.get("messages") for record in records):
        raise RuntimeError("release smoke export contains no decoded messages")


def main() -> None:
    options = arguments()
    binary = options.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"binary does not exist: {binary}")

    run_metadata_checks(binary)
    proxy_port = free_port()
    fixture = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    fixture_port = int(fixture.server_address[1])
    fixture_thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    fixture_thread.start()

    with tempfile.TemporaryDirectory(prefix="lens-release-smoke-") as directory:
        export = Path(directory) / "flows.jsonl"
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        process = subprocess.Popen(
            [
                str(binary),
                "run",
                "--headless",
                "--https",
                "passthrough",
                "--listen",
                f"127.0.0.1:{proxy_port}",
                "--export",
                str(export),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=creation_flags,
            start_new_session=os.name != "nt",
        )
        try:
            wait_for_listener(process, proxy_port)
            response = proxy_request(proxy_port, fixture_port)
            if b"200 OK" not in response or b"lens-dogfood-ok" not in response:
                raise RuntimeError(f"unexpected proxied response: {response[:512]!r}")
        finally:
            stdout, stderr, graceful = stop_process(process)
            fixture.shutdown()
            fixture.server_close()
            fixture_thread.join(timeout=5)

        if graceful:
            if "accepted:" not in stdout or "completed:" not in stdout:
                raise RuntimeError(f"Lens did not print final session counters\n{stdout}\n{stderr}")
            verify_export(export)

    print(f"release smoke passed on {sys.platform}")


if __name__ == "__main__":
    main()
