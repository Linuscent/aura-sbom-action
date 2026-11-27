"""Exercise the composite action against a synthetic, loopback-only endpoint."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time


HOST = "127.0.0.1"
API_KEY = "aura-smoke-not-a-secret"
PRODUCT_ID = "smoke-product"
VERSION = "v0.0.1-smoke"
CERT = "server.crt"
KEY = "server.key"
MAX_BYTES = 10 * 1024 * 1024
DEPENDENCY = {"is-number": "7.0.0"}


def write_fixture(workspace):
    fixture = workspace / "apps" / "smoke"
    fixture.mkdir(parents=True)
    package = {"name": "aura-smoke-fixture", "version": "0.0.1", "dependencies": DEPENDENCY}
    lockfile = {
        "name": package["name"],
        "version": package["version"],
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": package,
            "node_modules/is-number": {
                "version": "7.0.0",
                "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
                "license": "MIT",
                "engines": {"node": ">=0.12.0"},
            },
        },
    }
    for filename, data in (("package.json", package), ("package-lock.json", lockfile)):
        (fixture / filename).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def matches_upload(payload):
    if not isinstance(payload, dict) or set(payload) != {"projectId", "sbomContent"}:
        return False
    if payload["projectId"] != PRODUCT_ID or not isinstance(payload["sbomContent"], str):
        return False
    sbom = json.loads(payload["sbomContent"])
    if not isinstance(sbom, dict):
        return False
    metadata = sbom.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    return (
        sbom.get("bomFormat") == "CycloneDX"
        and sbom.get("specVersion") == "1.6"
        and isinstance(component, dict)
        and component.get("version") == VERSION
    )


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass  # Never echo paths, headers or bodies.

    def send_response(self, code, message=None):
        with (self.server.state / "responses").open("a", encoding="ascii") as responses:
            responses.write(f"{code}\n")
        super().send_response(code)

    def do_POST(self):
        if self.path != "/api/sbom/upload":
            self.send_error(404)
            return
        if self.headers.get_all("Authorization") != [f"Bearer {API_KEY}"]:
            self.send_error(401)
            return
        try:
            size = int(self.headers["Content-Length"])
            valid = (
                self.headers.get_content_type() == "application/json"
                and 0 < size <= MAX_BYTES
                and matches_upload(json.loads(self.rfile.read(size)))
            )
        except (ValueError, TypeError, OSError, RecursionError):
            valid = False
        if not valid:
            self.send_error(400, "Invalid smoke upload")
            return
        receipt = b'{"status":"accepted","upload":{"id":"smoke-upload"}}'
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(receipt)))
        self.end_headers()
        self.wfile.write(receipt)


class SmokeServer(HTTPServer):
    def __init__(self, state):
        self.state = state
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(state / CERT, state / KEY)
        super().__init__((HOST, 0), Handler)
        self.timeout = 0.2

    def get_request(self):
        connection, address = super().get_request()
        try:
            connection.settimeout(3)
            return self.tls.wrap_socket(connection, server_side=True), address
        except OSError:
            connection.close()
            raise

    def handle_error(self, _request, _address):
        pass  # Do not print request exceptions or tracebacks.


def serve(state):
    try:
        with SmokeServer(state) as server:
            (state / "port.tmp").write_text(str(server.server_port), encoding="ascii")
            (state / "port.tmp").rename(state / "port")
            deadline = time.monotonic() + 20 * 60
            while not (state / "stop").exists() and time.monotonic() < deadline:
                server.handle_request()
    finally:
        (state / "stopped").touch()


def wait_for(path, seconds, process=None):
    deadline = time.monotonic() + seconds
    while not path.exists():
        if time.monotonic() >= deadline or (process is not None and process.poll() is not None):
            raise RuntimeError("Smoke mock did not reach the requested state.")
        time.sleep(0.05)


def start(state):
    state.mkdir(mode=0o700)
    write_fixture(Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True))
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-days", "1", "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=IP:{HOST}",
            "-keyout", str(state / KEY), "-out", str(state / CERT),
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
    )
    process = subprocess.Popen(
        [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "_serve", str(state)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        wait_for(state / "port", 5, process)
        port = int((state / "port").read_text(encoding="ascii"))
        with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as env:
            env.write(f"AURA_SMOKE_ORIGIN=https://{HOST}:{port}\nAURA_SMOKE_CERT={state / CERT}\n")
    except Exception:
        process.kill()
        process.wait()
        (state / "stopped").touch()
        raise
    print("Loopback HTTPS smoke mock is ready.")


def stop(state):
    # Signal only our server through its private task directory; no PID reuse risk.
    if not (state / "port").is_file() or (state / "stopped").exists():
        return
    (state / "stop").touch()
    wait_for(state / "stopped", 10)


def verify(state):
    try:
        if (state / "responses").read_text(encoding="ascii").splitlines() != ["202"]:
            raise RuntimeError("Expected exactly one accepted POST.")
    finally:
        stop(state)
    print("Smoke mock accepted exactly one POST.")


def main(args):
    if len(args) == 2 and args[0] == "_serve":
        serve(Path(args[1]))
        return 0
    commands = {"start": start, "verify": verify, "stop": stop}
    if len(args) != 1 or args[0] not in commands:
        print("Usage: github_smoke.py start|verify|stop", file=sys.stderr)
        return 2
    try:
        state = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True) / "aura-smoke"
        commands[args[0]](state)
    except Exception:
        print(f"Smoke {args[0]} failed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
