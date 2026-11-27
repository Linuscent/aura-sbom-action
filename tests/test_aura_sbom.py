import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

import aura_sbom as action


ORIGIN = "https://aura.example.test"
KEY = " synthetic exact key "
FIXTURE = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {"component": {"name": "synthetic", "version": "generated"}},
}


class ActionTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.workspace = Path(temp.name).resolve()
        self.sbom = self.workspace / action.SBOM_FILE
        self.env = {
            "GITHUB_WORKSPACE": str(self.workspace),
            "AURA_LOCKFILE": "app/package-lock.json",
            "AURA_PRODUCT_ID": "sample-product_1",
            "AURA_ORIGIN": ORIGIN,
            "AURA_API_KEY": KEY,
        }

    def write_sbom(self, document=FIXTURE):
        self.sbom.write_text(json.dumps(document), encoding="utf-8")

    def run_action(self, mode):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = action.main(mode, self.env)
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_not_attempted(self):
        with patch.object(action.urllib.request, "build_opener") as opener:
            code, stdout, stderr = self.run_action("upload")
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("not attempted", stderr)
        self.assertNotIn(KEY.strip(), stderr)
        opener.assert_not_called()

    def test_lockfile_allowlist_and_nested_paths(self):
        lockdir = self.workspace / ".app-1"
        lockdir.mkdir()
        for name in action.LOCKFILES:
            with self.subTest(name=name):
                (lockdir / name).touch()
                action.validate_lockfile(self.workspace, f".app-1/{name}")

    def test_rejects_invalid_lockfile_paths(self):
        for path in (
            "", "/package-lock.json", "app/../yarn.lock", "./yarn.lock",
            "app//yarn.lock", "app\\yarn.lock", "app name/yarn.lock",
            "$HOME/yarn.lock", "$(id)/yarn.lock", "app;/yarn.lock",
            "app*/yarn.lock", "app/\tyarn.lock", "yarn.lock\n",
            "app/unknown.lock", "a" * 240 + "/yarn.lock",
        ):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    action.validate_lockfile(self.workspace, path)

    def test_lockfile_must_resolve_to_readable_regular_file_inside_workspace(self):
        lockfile = self.workspace / "yarn.lock"
        with self.assertRaises(FileNotFoundError):
            action.validate_lockfile(self.workspace, "yarn.lock")
        lockfile.mkdir()
        with self.assertRaises(ValueError):
            action.validate_lockfile(self.workspace, "yarn.lock")
        lockfile.rmdir()
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "yarn.lock"
            target.touch()
            lockfile.symlink_to(target)
            with self.assertRaises(ValueError):
                action.validate_lockfile(self.workspace, "yarn.lock")
        lockfile.unlink()
        target = self.workspace / "actual.lock"
        target.touch()
        lockfile.symlink_to(target.name)
        action.validate_lockfile(self.workspace, "yarn.lock")
        with patch.object(Path, "open", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                action.validate_lockfile(self.workspace, "yarn.lock")

    def test_validation_rejects_stale_output_including_dangling_link(self):
        lockfile = self.workspace / self.env["AURA_LOCKFILE"]
        lockfile.parent.mkdir()
        lockfile.touch()
        self.assertEqual(self.run_action("validate"), (0, "", ""))
        self.sbom.symlink_to("missing")
        code, stdout, stderr = self.run_action("validate")
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("existing aura-sbom.cdx.json", stderr)

    def test_exact_https_origin(self):
        for origin in (ORIGIN, f"{ORIGIN}/", f"{ORIGIN}:8443", "https://[2001:db8::1]/"):
            with self.subTest(origin=origin):
                self.assertEqual(action.upload_url(origin), origin.rstrip("/") + "/api/sbom/upload")
        for origin in (
            "", "http://aura.example.test", "https://", f"{ORIGIN}/path",
            f"{ORIGIN}//", f"{ORIGIN}?", f"{ORIGIN}#",
            "https://user:password@aura.example.test", "https://@aura.example.test",
            f"{ORIGIN}\\", f"{ORIGIN}\n", f" {ORIGIN}", f"{ORIGIN}:",
            f"{ORIGIN}:0", f"{ORIGIN}:65536", "https://[not-ipv6]",
            "https://aura..example.test", "https://%61ura.example.test",
        ):
            with self.subTest(origin=origin):
                with self.assertRaises(ValueError):
                    action.upload_url(origin)

    def test_input_failures_do_not_open_network(self):
        self.write_sbom()
        for name, bad_value in (
            ("AURA_API_KEY", ""),
            ("AURA_API_KEY", "synthetic\nkey"),
            ("AURA_PRODUCT_ID", "wrong/product"),
            ("AURA_ORIGIN", f"{ORIGIN}/not-an-origin"),
        ):
            with self.subTest(name=name), patch.dict(self.env, {name: bad_value}):
                self.assert_not_attempted()

    def test_invalid_sbom_and_independent_size_limits(self):
        self.assert_not_attempted()
        self.sbom.symlink_to("missing")
        self.assert_not_attempted()
        self.sbom.unlink()
        self.write_sbom({"bomFormat": "SPDX"})
        self.assert_not_attempted()
        self.sbom.write_bytes(b"invalid JSON")
        self.assert_not_attempted()
        self.write_sbom()
        with patch.object(action, "MAX_BYTES", 16):
            self.assert_not_attempted()
        # A file right at the limit can still yield an oversized JSON request.
        with patch.object(action, "MAX_BYTES", self.sbom.stat().st_size):
            self.assert_not_attempted()

    def test_local_upload_uses_only_cyclonedx_and_optional_component_version(self):
        self.write_sbom()
        for value, expected in (("", "generated"), ("v2.1", "v2.1")):
            with self.subTest(value=value):
                request = action.build_request(self.workspace, "test-id", ORIGIN, KEY, value)
                self.assertEqual(request.full_url, f"{ORIGIN}/api/sbom/upload")
                self.assertEqual(request.get_method(), "POST")
                self.assertEqual(request.headers["Authorization"], "Bearer " + KEY)
                self.assertEqual(request.get_header("Content-type"), "application/json")
                body = json.loads(request.data)
                self.assertEqual(set(body), {"projectId", "sbomContent"})
                self.assertEqual(body["projectId"], "test-id")
                document = json.loads(body["sbomContent"])
                self.assertEqual(document["metadata"]["component"]["version"], expected)
                self.assertEqual(document["specVersion"], "1.6")
                self.assertEqual(json.loads(self.sbom.read_text(encoding="utf-8")), FIXTURE)
        document = {"bomFormat": "CycloneDX", "metadata": {"component": None}}
        self.write_sbom(document)
        request = action.build_request(self.workspace, "test-id", ORIGIN, KEY, "v2.1")
        self.assertEqual(json.loads(json.loads(request.data)["sbomContent"]), document)

    def mock_opener(self):
        factory = self.enter_mock(patch.object(action.urllib.request, "build_opener"))
        return factory, factory.return_value.open

    def enter_mock(self, patcher):
        self.addCleanup(patcher.stop)
        return patcher.start()

    def test_upload_accepts_verified_receipt_and_does_not_log_receipt_data(self):
        self.write_sbom()
        factory, open_request = self.mock_opener()
        response = open_request.return_value.__enter__.return_value
        response.status = 202
        response.read.return_value = b'{"status":"accepted","upload":{"id":"synthetic-receipt"}}'
        self.assertEqual(self.run_action("upload"), (0, action.ACCEPTED + "\n", ""))
        factory.assert_called_once_with(action.NoRedirect)
        open_request.assert_called_once()
        self.assertEqual(open_request.call_args.kwargs, {"timeout": 60})
        request = open_request.call_args.args[0]
        document = json.loads(json.loads(request.data)["sbomContent"])
        self.assertEqual(document, FIXTURE)
        response.read.assert_called_once_with(action.RECEIPT_MAX_BYTES + 1)

    def test_redirect_handler_declines_redirects(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                self.assertIsNone(
                    action.NoRedirect().redirect_request(
                        Mock(), Mock(), status, "", {}, "https://untrusted.example.test"
                    )
                )

    def test_network_failures_are_uncertain_sanitized_and_not_retried(self):
        self.write_sbom()
        _, open_request = self.mock_opener()
        for failure in (
            TimeoutError("private details"),
            HTTPError(ORIGIN, 302, "private details", {}, None),
            HTTPError(ORIGIN, 403, "private details", {}, None),
        ):
            with self.subTest(failure=type(failure)):
                open_request.reset_mock()
                open_request.side_effect = failure
                self.assertEqual(self.run_action("upload"), (1, "", action.UPLOAD_UNCONFIRMED + "\n"))
                open_request.assert_called_once()

    def test_receipt_failures_are_uncertain_sanitized_and_not_retried(self):
        self.write_sbom()
        _, open_request = self.mock_opener()
        response = open_request.return_value.__enter__.return_value
        accepted = b'{"status":"accepted","upload":{"id":"synthetic-receipt"}}'
        for status, body in (
            (200, accepted),
            (202, b"private details"),
            (202, b'["accepted"]'),
            (202, b'{"status":"accepted","upload":{"id":17}}'),
            (202, b'{"status":"accepted","upload":{"id":""}}'),
            (202, b'{"status":"queued","upload":{"id":"synthetic-receipt"}}'),
            (202, accepted.ljust(action.RECEIPT_MAX_BYTES + 1)),
        ):
            with self.subTest(status=status, length=len(body)):
                open_request.reset_mock()
                response.status, response.read.return_value = status, body
                self.assertEqual(self.run_action("upload"), (1, "", action.UPLOAD_UNCONFIRMED + "\n"))
                open_request.assert_called_once()


if __name__ == "__main__":
    unittest.main()
