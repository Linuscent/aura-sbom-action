"""Validate the generator input and submit one SBOM to Aura."""

import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import sys
import urllib.request


LOCKFILES = frozenset(
    """
    package-lock.json pnpm-lock.yaml yarn.lock bun.lock requirements.txt
    poetry.lock Pipfile.lock uv.lock Cargo.lock go.mod go.sum Gemfile.lock
    composer.lock packages.lock.json pubspec.lock conan.lock Package.resolved
    """.split()
)
SBOM_FILE = "aura-sbom.cdx.json"
MAX_BYTES = 10 * 1024 * 1024
RECEIPT_MAX_BYTES = 64 * 1024
TIMEOUT_SECONDS = 60
ACCEPTED = "Aura accepted the SBOM for asynchronous analysis. A new release was created."
UPLOAD_UNCONFIRMED = (
    "Aura upload failed or its outcome is unknown. Inspect the product's releases "
    "before retrying: each accepted upload creates a release."
)


def validate_lockfile(workspace, lockfile):
    parts = lockfile.split("/")
    if (
        len(lockfile) > 240
        or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", lockfile)
        or any(part in {".", ".."} for part in parts)
        or parts[-1] not in LOCKFILES
    ):
        raise ValueError("invalid lockfile path")
    target = (workspace / lockfile).resolve(strict=True)
    if not target.is_relative_to(workspace) or not target.is_file():
        raise ValueError("invalid lockfile target")
    with target.open("rb"):
        pass


def upload_url(origin):
    # Use a full match before interpreting the host: URL parsers may silently
    # strip control characters or accept empty query/fragment delimiters.
    match = re.fullmatch(
        r"https://(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::([0-9]{1,5}))?/?",
        origin,
    )
    if not match:
        raise ValueError("invalid HTTPS origin")
    host, port = match.groups()
    if host.startswith("["):
        ipaddress.IPv6Address(host[1:-1])
    elif len(host.rstrip(".")) > 253 or any(
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in host.removesuffix(".").split(".")
    ):
        raise ValueError("invalid HTTPS host")
    if port is not None and not 1 <= int(port) <= 65535:
        raise ValueError("invalid HTTPS port")
    return origin.removesuffix("/") + "/api/sbom/upload"


def build_request(workspace, product_id, origin, key, version):
    url = upload_url(origin)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", product_id):
        raise ValueError("invalid product ID")
    # Do not normalize credentials. Reject values unusable in an HTTP header.
    if not key or any(ord(char) < 32 or ord(char) == 127 for char in key):
        raise ValueError("invalid API key")
    key.encode("latin-1")

    path = workspace / SBOM_FILE
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("invalid SBOM file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("SBOM file too large")
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ValueError("invalid SBOM format")
    metadata = document.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if version and isinstance(component, dict):
        component["version"] = version
    body = json.dumps(
        {"projectId": product_id, "sbomContent": json.dumps(document, allow_nan=False)}
    ).encode("utf-8")
    if len(body) > MAX_BYTES:
        raise ValueError("request body too large")
    return urllib.request.Request(
        url,
        data=body,
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
        method="POST",
    )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _deadline(signum, frame):
    raise TimeoutError


def upload(request):
    # urllib's timeout bounds socket operations, not the whole upload/receipt.
    # Also bound elapsed time in this short-lived Linux runner process.
    previous_handler = signal.signal(signal.SIGALRM, _deadline)
    signal.alarm(TIMEOUT_SECONDS)
    try:
        opener = urllib.request.build_opener(NoRedirect)
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            if response.status != 202:
                raise ValueError("unexpected HTTP status")
            raw = response.read(RECEIPT_MAX_BYTES + 1)
        if len(raw) > RECEIPT_MAX_BYTES:
            raise ValueError("receipt too large")
        receipt = json.loads(raw)
        accepted_upload = receipt.get("upload") if isinstance(receipt, dict) else None
        if not (
            isinstance(accepted_upload, dict)
            and receipt.get("status") == "accepted"
            and isinstance(accepted_upload.get("id"), str)
            and accepted_upload["id"]
        ):
            raise ValueError("invalid accepted receipt")
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)


def main(mode, env):
    if mode == "validate":
        try:
            workspace = Path(env["GITHUB_WORKSPACE"]).resolve(strict=True)
            validate_lockfile(workspace, env["AURA_LOCKFILE"])
            output = workspace / SBOM_FILE
            output_exists = output.is_symlink() or output.exists()
        except Exception:
            print("Choose a supported, readable lockfile inside the repository.", file=sys.stderr)
            return 1
        if output_exists:
            print("Remove the existing aura-sbom.cdx.json output before running this action.", file=sys.stderr)
            return 1
        return 0

    if mode != "upload":
        return 1
    try:
        workspace = Path(env["GITHUB_WORKSPACE"]).resolve(strict=True)
        request = build_request(
            workspace,
            env["AURA_PRODUCT_ID"],
            env["AURA_ORIGIN"],
            env["AURA_API_KEY"],
            env.get("AURA_RELEASE_VERSION", ""),
        )
    except Exception:
        print(
            "Aura upload was not attempted. Check the product ID, HTTPS origin, "
            "API key and generated CycloneDX SBOM (10 MiB file and request limits).",
            file=sys.stderr,
        )
        return 1
    try:
        upload(request)
    except Exception:
        print(UPLOAD_UNCONFIRMED, file=sys.stderr)
        return 1
    print(ACCEPTED)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], os.environ))
