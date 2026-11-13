# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Regression checks for the client's HTTP keep-alive pool and capabilities cache.

Contributed by an outside tester (a ChatGPT sandbox agent on airc.dev, 2026-10-22) with the pool
patch; adopted by Rafael. The same patch's send-over-WebSocket route was measured slower on
airc.dev and left out, with its tests."""
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sys
import threading
import unittest
from unittest.mock import AsyncMock, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from airc.httpclient import HttpClient


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.lock = threading.Lock()
        self.connections = 0
        self.requests = []
        self.drop_get_once = True
        super().__init__(("127.0.0.1", 0), Handler)

    def get_request(self):
        result = super().get_request()
        with self.lock:
            self.connections += 1
        return result


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, value, close=False):
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def drop(self):
        self.close_connection = True
        self.connection.shutdown(socket.SHUT_RDWR)
        self.connection.close()

    def do_GET(self):
        with self.server.lock:
            self.server.requests.append(("GET", self.path))
            drop = self.path == "/drop-once" and self.server.drop_get_once
            if drop:
                self.server.drop_get_once = False
        if drop:
            self.drop()
        elif self.path.startswith("/.well-known/airc"):
            self.reply({"t": "capabilities", "realm": "test.invalid", "features": ["ws"]})
        else:
            self.reply({"path": self.path}, close=self.path == "/close")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        with self.server.lock:
            self.server.requests.append(("POST", self.path))
        if self.path == "/drop-post":
            self.drop()
        else:
            self.reply({"ok": True})


class PersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = Server()
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.02), daemon=True)
        self.thread.start()
        self.client = HttpClient("http://127.0.0.1:" + str(self.server.server_port), None)

    async def asyncTearDown(self):
        await self.client.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    async def test_sequential_reads_reuse_one_connection(self):
        for index in range(4):
            result = await self.client._request("GET", "/item/" + str(index), auth=False)
            self.assertEqual(result, {"path": "/item/" + str(index)})
        self.assertEqual(self.server.connections, 1)

    async def test_capabilities_discovered_once_with_explicit_refresh(self):
        results = await asyncio.gather(*(self.client.capabilities() for _ in range(8)))
        self.assertTrue(all(result["realm"] == "test.invalid" for result in results))
        self.assertEqual(len(self.server.requests), 1)
        await self.client.capabilities(refresh=True)
        self.assertEqual(len(self.server.requests), 2)
        self.assertEqual(self.server.connections, 1)

    async def test_concurrent_requests_have_independent_connections(self):
        results = await asyncio.gather(*(self.client._request("GET", "/item/" + str(i), auth=False) for i in range(8)))
        self.assertEqual([result["path"] for result in results], ["/item/" + str(i) for i in range(8)])
        self.assertLessEqual(len(self.client._http_idle), 4)

    async def test_server_connection_close_is_honored(self):
        await self.client._request("GET", "/close", auth=False)
        await self.client._request("GET", "/next", auth=False)
        self.assertEqual(self.server.connections, 2)

    async def test_stale_connection_can_retry_safe_get(self):
        await self.client._request("GET", "/warmup", auth=False)
        result = await self.client._request("GET", "/drop-once", auth=False)
        self.assertEqual(result, {"path": "/drop-once"})
        self.assertEqual(self.server.requests.count(("GET", "/drop-once")), 2)
        self.assertEqual(self.server.connections, 2)

    async def test_ambiguous_post_is_not_retried(self):
        await self.client._request("GET", "/warmup", auth=False)
        with self.assertRaises(Exception):
            await self.client._request("POST", "/drop-post", {"value": 1}, auth=False)
        self.assertEqual(self.server.requests.count(("POST", "/drop-post")), 1)

    async def test_binary_section_stays_on_http(self):
        ws = Mock()
        ws.closed = False
        ws.request = AsyncMock()
        self.client._ws = ws
        self.client._request_sync = Mock(return_value={"status": "delivered"})
        message = {"t": "msg", "_bin": b"binary-data"}
        result = await self.client._request("POST", "/airc/v0/send", message)
        self.assertEqual(result["status"], "delivered")
        ws.request.assert_not_awaited()
        self.client._request_sync.assert_called_once()
        self.client._ws = None


if __name__ == "__main__":
    unittest.main()
