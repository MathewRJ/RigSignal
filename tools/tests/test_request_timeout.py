import importlib.util
import socket
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("install_assets", ROOT / "tools/install_assets.py")
INSTALL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(INSTALL)


@contextmanager
def endpoint(response=None):
    stop = threading.Event()
    accepted = threading.Event()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.1)

        def serve():
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    accepted.set()
                    if response is None:
                        stop.wait()  # Accept, but never send an HTTP response.
                    else:
                        connection.settimeout(2)
                        request = b""
                        while b"\r\n\r\n" not in request:
                            chunk = connection.recv(4096)
                            if not chunk:
                                return
                            request += chunk
                        connection.sendall(response)
                return

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{listener.getsockname()[1]}", accepted
        finally:
            stop.set()
            thread.join(timeout=2)


class RequestTimeoutTests(unittest.TestCase):
    def test_normal_response_returns_status_and_body(self):
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
        with endpoint(response) as (base, accepted):
            self.assertEqual(INSTALL.request_response(base, "/", "GET", "Basic x"), (200, b"hello"))
            self.assertTrue(accepted.is_set())

    def test_stalled_response_raises_request_failure_within_bound(self):
        # Keep the real socket test quick while production uses 30 seconds.
        # create=True lets the unchanged implementation demonstrate its hang.
        with endpoint() as (base, accepted), patch.object(
                INSTALL, "REQUEST_TIMEOUT_SECONDS", 0.5, create=True):
            started = time.monotonic()
            with self.assertRaises(INSTALL.RequestFailure) as failure:
                INSTALL.request_response(base, "/", "GET", "Basic x")
            elapsed = time.monotonic() - started
            self.assertTrue(accepted.is_set())
            self.assertLess(elapsed, 30)
            self.assertIsNone(failure.exception.status)
            self.assertIn("network timeout after 0.5s", str(failure.exception))

    def test_production_timeout_is_defined_and_under_the_poll_bound(self):
        # The two tests above patch REQUEST_TIMEOUT_SECONDS to keep themselves quick,
        # and they use create=True so the pre-fix implementation can demonstrate its
        # hang. That means neither of them would notice if the production constant
        # were deleted or set to 600 -- the patch would simply recreate or override
        # it. This test is the one that pins the shipped value.
        #
        # The bound that matters is the prerequisite poll's 60 s deadline, which is
        # only evaluated AFTER each request returns. A per-request timeout at or
        # above that deadline lets a single stalled endpoint outlive the poll, which
        # is the defect this module was changed to fix.
        timeout = INSTALL.REQUEST_TIMEOUT_SECONDS      # no create=True crutch: must exist
        self.assertIsInstance(timeout, (int, float))
        self.assertGreater(timeout, 0)
        self.assertLess(timeout, 60)


if __name__ == "__main__":
    unittest.main()
