#!/usr/bin/env python3
"""Loopback-only controller for the installation-media welcome application."""

import argparse
import hashlib
import http.server
import json
import os
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

MAX_REQUEST = 16 * 1024
MAX_COMMAND_OUTPUT = 1024 * 1024
MAX_DIAGNOSTICS = 128 * 1024
MAX_STATIC_FILE = 2 * 1024 * 1024
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/opemos.svg": ("opemos.svg", "image/svg+xml"),
    "/assets/install.svg": ("assets/install.svg", "image/svg+xml"),
    "/assets/recovery.svg": ("assets/recovery.svg", "image/svg+xml"),
    "/assets/gaming.svg": ("assets/gaming.svg", "image/svg+xml"),
}


class Controller:
    def __init__(self, args):
        self.mock = args.mock
        self.ui_root = args.ui_root.resolve()
        self.runtime = args.runtime.resolve()
        self.helper = Path(args.helper)
        self.rollback = Path(args.rollback)
        self.state_root = Path(args.state_root)
        self.token = os.urandom(32).hex()
        self.nonce = os.urandom(18).hex()
        self.origin = ""
        self.httpd = None
        self.lock = threading.Lock()
        self.operation = {
            "schemaVersion": 1,
            "status": "idle",
            "phase": "ready",
            "progress": 0,
            "message": "Choose an operation.",
            "terminal": False,
        }
        self.operation_marker = self.runtime / "operation-running"

    def run_command(self, argv, timeout=30):
        process = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        payload = process.stdout[: MAX_COMMAND_OUTPUT + 1]
        if len(payload) > MAX_COMMAND_OUTPUT:
            raise RuntimeError("The helper returned excessive output.")
        text = payload.decode("utf-8", "replace")
        if process.returncode != 0:
            summary = " ".join(text.split())[-600:]
            raise RuntimeError(summary or f"The helper exited with status {process.returncode}.")
        return text

    @staticmethod
    def clean(value, maximum=256):
        if not isinstance(value, str) or not value or len(value) > maximum:
            raise ValueError("A request field is missing or invalid.")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("A request field contains control data.")
        return value

    def bootstrap(self):
        if self.mock:
            return {
                "schemaVersion": 1,
                "mode": "simulation",
                "nvidiaVersion": "575.64.05",
                "supportRevision": "cbc442704406",
                "environment": "macOS safe preview",
                "disks": [
                    {
                        "device": "/dev/vda",
                        "bytes": 32_000_000_000,
                        "identity": "1" * 64,
                        "model": "Synthetic SteamOS target",
                        "serial": "SYNTHETIC-001",
                        "transport": "VirtIO",
                        "layout": "blank",
                    }
                ],
            }
        media = self.run_command([str(self.helper), "media-info"])
        values = {}
        for line in media.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value
        if values.get("status") != "ready":
            raise RuntimeError("Installation-media identity is unavailable.")
        inventory = self.run_command([str(self.helper), "inventory"])
        disks = []
        for line in inventory.splitlines():
            fields = line.split("\t")
            if len(fields) != 7:
                raise RuntimeError("The disk inventory returned an unsupported record.")
            device, byte_text, identity, model, serial, transport, layout = fields
            if not device.startswith("/dev/") or not identity or len(identity) != 64:
                raise RuntimeError("The disk inventory returned an unsafe identity.")
            disks.append({
                "device": device,
                "bytes": int(byte_text),
                "identity": identity,
                "model": model or "Unknown model",
                "serial": serial or "Not reported",
                "transport": transport or "Unknown bus",
                "layout": layout,
            })
        return {
            "schemaVersion": 1,
            "mode": "live",
            "nvidiaVersion": values.get("nvidiaVersion", "unknown"),
            "supportRevision": values.get("supportRevision", "")[:12],
            "environment": "SteamOS recovery media",
            "disks": disks,
        }

    def update_operation(self, **values):
        with self.lock:
            self.operation = {**self.operation, **values}

    def operation_status(self):
        with self.lock:
            return dict(self.operation)

    def require_idle(self):
        with self.lock:
            if self.operation["status"] == "running":
                raise RuntimeError("Disk mutation is active; this operation is unavailable until it finishes.")

    def start_install(self, document):
        mode = self.clean(document.get("mode"))
        device = self.clean(document.get("device"))
        identity = self.clean(document.get("identity"))
        confirmation = self.clean(document.get("confirmation"))
        if mode not in ("all", "system"):
            raise ValueError("The installation mode is unsupported.")
        basename = device.rsplit("/", 1)[-1]
        phrase = f"{'ERASE' if mode == 'all' else 'REINSTALL'} {basename}"
        if confirmation != phrase or len(identity) != 64 or any(c not in "0123456789abcdef" for c in identity):
            raise ValueError("The confirmation or disk identity did not match.")
        with self.lock:
            if self.operation["status"] == "running":
                raise RuntimeError("An installation is already running.")
            descriptor = os.open(self.operation_marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                self.operation = {
                    "schemaVersion": 1,
                    "status": "running",
                    "phase": "validating",
                    "progress": 4,
                    "message": "Revalidating the selected physical disk.",
                    "terminal": False,
                }
            finally:
                os.close(descriptor)
        thread = threading.Thread(
            target=self._mock_install if self.mock else self._live_install,
            args=(mode, device, identity, confirmation),
            daemon=True,
        )
        thread.start()
        return self.operation_status()

    def _mock_install(self, _mode, _device, _identity, _confirmation):
        stages = [
            (18, "preparing", "Preparing the target layout."),
            (55, "installing", "Running the protected Valve installation."),
            (76, "slot-a", "Installing recovery into rootfs-A."),
            (89, "slot-b", "Installing recovery into rootfs-B."),
            (96, "verifying", "Independently verifying both A/B guardians."),
        ]
        for progress, phase, message in stages:
            time.sleep(0.35)
            self.update_operation(progress=progress, phase=phase, message=message)
        time.sleep(0.35)
        self.update_operation(
            status="complete", phase="complete", progress=100,
            message="Synthetic installation and A/B verification completed.", terminal=True,
        )
        self.operation_marker.unlink(missing_ok=True)

    def _live_install(self, mode, device, identity, confirmation):
        command = [
            "sudo", str(self.helper), "install", mode, device, identity,
            "--confirm", confirmation,
        ]
        log_directory = self.state_root
        try:
            if log_directory.is_symlink():
                raise RuntimeError("The installer log directory is unsafe.")
            log_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(log_directory, 0o700)
            log_path = log_directory / time.strftime("install-%Y%m%d-%H%M%S.log")
            process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, start_new_session=True,
            )
            total = 0
            with log_path.open("x", encoding="utf-8") as output:
                os.chmod(log_path, 0o600)
                for line in process.stdout:
                    total += len(line.encode("utf-8", "replace"))
                    if total > MAX_COMMAND_OUTPUT:
                        os.killpg(process.pid, signal.SIGTERM)
                        raise RuntimeError("The installer returned excessive output.")
                    output.write(line)
                    output.flush()
                    message = " ".join(line.split())[:500]
                    if message:
                        lowered = message.lower()
                        progress, phase = 24, "installing"
                        if "rootfs-a" in lowered:
                            progress, phase = 68, "slot-a"
                        elif "rootfs-b" in lowered:
                            progress, phase = 82, "slot-b"
                        elif "verif" in lowered or "guardian" in lowered:
                            progress, phase = 92, "verifying"
                        elif "partition" in lowered or "format" in lowered:
                            progress, phase = 18, "preparing"
                        self.update_operation(message=message, progress=progress, phase=phase)
            status = process.wait()
            if status != 0:
                raise RuntimeError(f"Installation stopped with status {status}. Review diagnostics before booting the target.")
            marker = log_directory / "last-install-log"
            descriptor, temporary = tempfile.mkstemp(prefix=".last-install-log-", dir=log_directory)
            try:
                os.fchmod(descriptor, 0o600)
                os.write(descriptor, (str(log_path) + "\n").encode("utf-8"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, marker)
            self.update_operation(
                status="complete", phase="complete", progress=100,
                message="Installation and A/B recovery verification completed.", terminal=True,
            )
            self.operation_marker.unlink(missing_ok=True)
        except Exception as error:
            self.update_operation(
                status="failed", phase="failed", progress=100,
                message=str(error)[:700], terminal=True,
            )
            self.operation_marker.unlink(missing_ok=True)

    def diagnostics(self):
        if self.mock:
            return {
                "schemaVersion": 1,
                "text": "Safe simulation\n\nSynthetic target: /dev/vda (eligible)\nNo disks, privileges, or installers are reachable.",
            }
        sections = []
        for operation in ("media-info", "inventory-report"):
            try:
                sections.append(self.run_command([str(self.helper), operation]))
            except Exception as error:
                sections.append(f"{operation}: {error}")
        marker = self.state_root / "last-install-log"
        try:
            if marker.is_file() and not marker.is_symlink():
                log = Path(marker.read_text(encoding="utf-8")[:4096].strip())
                root = self.state_root.resolve()
                if log.is_file() and not log.is_symlink() and log.resolve().parent == root:
                    sections.append("Last installation log\n" + log.read_text(encoding="utf-8")[-65536:])
        except OSError:
            pass
        return {"schemaVersion": 1, "text": "\n\n".join(sections)[:MAX_DIAGNOSTICS]}

    def power(self, action):
        self.require_idle()
        if action not in ("stay", "restart", "shutdown"):
            raise ValueError("The requested completion action is unsupported.")
        if self.mock or action == "stay":
            return {"schemaVersion": 1, "status": "simulated" if self.mock else "ready", "action": action}
        subprocess.Popen(
            ["systemctl", "reboot" if action == "restart" else "poweroff"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return {"schemaVersion": 1, "status": "requested", "action": action}

    def rollback_action(self):
        self.require_idle()
        if self.mock:
            return {"schemaVersion": 1, "status": "simulated"}
        if not self.rollback.is_file() or self.rollback.is_symlink():
            raise RuntimeError("The recovery tool is unavailable.")
        terminal = next((tool for tool in ("konsole", "xterm") if shutil_which(tool)), None)
        if terminal is None:
            raise RuntimeError("A recovery terminal is unavailable.")
        command = [terminal, "-e", "sudo", str(self.rollback)]
        subprocess.Popen(command, stdin=subprocess.DEVNULL, start_new_session=True)
        return {"schemaVersion": 1, "status": "opened"}

    def close(self):
        self.require_idle()
        browser_pid = self.runtime / "browser.pid"
        try:
            value = browser_pid.read_text(encoding="ascii").strip()
            if value.isdigit() and int(value) > 1:
                threading.Timer(0.15, lambda: os.kill(int(value), signal.SIGTERM)).start()
        except (OSError, ValueError, ProcessLookupError):
            pass
        threading.Timer(0.25, self.httpd.shutdown).start()


def shutil_which(name):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "OPEMOSWelcome/1"

    def log_message(self, _format, *_args):
        return

    @property
    def controller(self):
        return self.server.controller

    def send_payload(self, status, payload, content_type="application/json; charset=utf-8"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", f"default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self' 'nonce-{self.controller.nonce}'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        return (
            self.headers.get("X-OPEMOS-Token") == self.controller.token
            and self.headers.get("Origin") == self.controller.origin
        )

    def do_GET(self):
        path = urlsplit(self.path).path
        if path.startswith("/api/"):
            if not self.authorized():
                self.send_payload(403, {"error": "The welcome session is unauthorized."})
                return
            try:
                if path == "/api/bootstrap":
                    result = self.controller.bootstrap()
                elif path == "/api/status":
                    result = self.controller.operation_status()
                elif path == "/api/diagnostics":
                    result = self.controller.diagnostics()
                else:
                    self.send_payload(404, {"error": "Unknown operation."})
                    return
                self.send_payload(200, result)
            except Exception as error:
                self.send_payload(500, {"error": str(error)[:700]})
            return
        record = STATIC_FILES.get(path)
        if record is None:
            self.send_payload(404, b"Not found\n", "text/plain; charset=utf-8")
            return
        relative, content_type = record
        candidate = (self.controller.ui_root / relative).resolve()
        if candidate.parent != self.controller.ui_root and self.controller.ui_root not in candidate.parents:
            self.send_payload(404, b"Not found\n", "text/plain; charset=utf-8")
            return
        try:
            if candidate.is_symlink() or not candidate.is_file():
                raise OSError("The requested asset is unsafe.")
            body = candidate.read_bytes()
            if len(body) > MAX_STATIC_FILE:
                raise OSError("The requested asset is excessive.")
            if path in ("/", "/index.html"):
                body = body.replace(b'"__OPEMOS_SESSION_TOKEN__"', json.dumps(self.controller.token).encode())
                body = body.replace(b"__OPEMOS_CSP_NONCE__", self.controller.nonce.encode("ascii"))
            self.send_payload(200, body, content_type)
        except OSError:
            self.send_payload(404, b"Not found\n", "text/plain; charset=utf-8")

    def do_POST(self):
        path = urlsplit(self.path).path
        if not self.authorized():
            self.send_payload(403, {"error": "The welcome session is unauthorized."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_REQUEST or self.headers.get("Content-Type") != "application/json":
                raise ValueError("The request is malformed or excessive.")
            document = json.loads(self.rfile.read(length))
            if not isinstance(document, dict):
                raise ValueError("The request has an unsupported shape.")
            if path == "/api/install":
                result = self.controller.start_install(document)
            elif path == "/api/power":
                result = self.controller.power(document.get("action"))
            elif path == "/api/rollback":
                result = self.controller.rollback_action()
            elif path == "/api/close":
                result = {"schemaVersion": 1, "status": "closing"}
                self.controller.close()
            else:
                self.send_payload(404, {"error": "Unknown operation."})
                return
            self.send_payload(200, result)
        except (ValueError, json.JSONDecodeError) as error:
            self.send_payload(400, {"error": str(error)[:700]})
        except Exception as error:
            self.send_payload(500, {"error": str(error)[:700]})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ui-root", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--helper", default="/usr/lib/opemos-install-media/opemos-install-helper")
    parser.add_argument("--rollback", default="/home/deck/tools/opemos-rollback-last-update")
    parser.add_argument("--state-root", default="/home/deck/.local/state/open-opemos")
    parser.add_argument("--mock", action="store_true")
    args = parser.parse_args()
    args.runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.runtime, 0o700)
    controller = Controller(args)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.controller = controller
    controller.httpd = server
    controller.origin = f"http://127.0.0.1:{server.server_port}"
    port_file = args.runtime / "port"
    port_file.write_text(str(server.server_port) + "\n", encoding="ascii")
    os.chmod(port_file, 0o600)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
