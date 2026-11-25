import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import server

TOKEN = b"test-secret-" + b"a" * 40

class LogApi(unittest.TestCase):
    def setUp(self):
        state = tempfile.TemporaryDirectory()
        self.addCleanup(state.cleanup)
        self.dir = Path(state.name)
        self.log = self.dir / "app.log"
        self.log.write_bytes(b"first\r\n\n" + b"".join(f"row {i}\n".encode() for i in range(2500)) + b"last")
        self.sock = server.Server(("127.0.0.1", 0), TOKEN, {
            "file": ("file", str(self.log)),
            "docker": ("docker", "allowed-container"),
        })
        worker = threading.Thread(target=self.sock.serve_forever, kwargs={"poll_interval": 0.01})
        worker.start()
        self.addCleanup(worker.join, 2)
        self.addCleanup(self.sock.server_close)
        self.addCleanup(self.sock.shutdown)

    def get(self, path, token=TOKEN):
        headers = {} if token is None else {"Authorization": "Bearer " + token.decode()}
        conn = http.client.HTTPConnection(*self.sock.server_address, timeout=3)
        try:
            conn.request("GET", path, headers=headers)
            res = conn.getresponse()
            return res.status, json.loads(res.read())
        finally:
            conn.close()

    def lines(self, name, params):
        return self.get(f"/v1/sources/{name}/lines?{params}")

    def test_auth_sources_and_unknown_id(self):
        self.assertEqual(self.get("/v1/sources", None)[0], 401)
        self.assertEqual(self.get("/v1/sources", b"wrong")[0], 401)
        s, result = self.get("/v1/sources")
        self.assertEqual(s, 200)
        self.assertEqual(result, {"sources": [{"id":"file","kind":"file"},{"id":"docker","kind":"docker"}]})
        self.assertEqual(self.lines("unconfigured", "limit=1")[0], 404)
        for params in ("path=/etc/passwd", "container=other", "offset=3&offset=0",
                       "mode=tail&offset=1", "limit=1001", "limit=0", "offset=-1"):
            self.assertEqual(self.lines("file", params)[0], 400)

    def test_head_offset_and_tail(self):
        self.assertEqual(self.lines("file", "limit=3")[1]["lines"], ["first", "", "row 0"])
        result = self.lines("file", "offset=1000&limit=1000")[1]
        self.assertEqual((result["offset"], len(result["lines"]), result["lines"][:1], result["lines"][-1:]),
                         (1000, 1000, ["row 998"], ["row 1997"]))
        self.assertEqual(self.lines("file", "mode=tail&limit=3")[1]["lines"], ["row 2498", "row 2499", "last"])
        self.assertEqual(self.lines("file", "offset=3000")[1]["lines"], [])
        self.log.write_bytes(b"\n\n")
        self.assertEqual(self.lines("file", "mode=tail")[1]["lines"], ["", ""])
        self.log.write_bytes(b"")
        self.assertEqual(self.lines("file", "mode=tail")[1]["lines"], [])

    def test_path_auth_for_listing_and_reading(self):
        key = TOKEN.decode()
        base = f"/t/{key}/v1/sources"
        status, payload = self.get(base, None)
        self.assertEqual(status, 200)
        self.assertNotIn(key, json.dumps(payload))
        status, payload = self.get(base + "/file/lines?mode=tail&limit=1", None)
        self.assertEqual((status, payload["lines"]), (200, ["last"]))
        self.assertEqual(self.get(base + "/unconfigured/lines", None)[0], 404)
        for wrong in ("b"*64, key[:-1], "%61" + key[1:]):
            with self.subTest(wrong=wrong):
                self.assertEqual(self.get(f"/t/{wrong}/v1/sources"),
                                 (401, {"error": "unauthorized"}))
        self.assertEqual(self.get(f"/v1/sources?token={key}", None)[0], 401)

    def test_container_inventory_has_fixed_fields_and_does_not_grant_log_access(self):
        cli = self.dir / "docker"
        cli.write_text("""#!/bin/sh
set -eu
[ "$1,$2,$3,$4" = '--host,unix:///var/run/docker.sock,ps,--format' ]
[ "$#" = 5 ] || [ "$6" = '--all' ]
printf '%s\\n' '{"id":"abc","name":"outside","image":"app:1","state":"running","status":"Up","ports":"127.0.0.1:8100->8080/tcp"}'
if [ "$#" = 6 ]; then
  printf '%s\\n' '{"id":"def","name":"stopped","image":"app:1","state":"exited","status":"Exited","ports":""}'
fi
""")
        cli.chmod(0o700)
        with patch.dict(os.environ, PATH=f"{self.dir}:{os.environ['PATH']}"):
            self.assertEqual(self.get("/v1/containers", None)[0], 401)
            status, result = self.get("/v1/containers")
            self.assertEqual((status, len(result["containers"])), (200, 1))
            self.assertEqual(result["containers"][0]["ports"], "127.0.0.1:8100->8080/tcp")
            self.assertEqual(self.get(f"/t/{TOKEN.decode()}/v1/containers?all=1", None)[1]["containers"][1]["state"], "exited")
            self.assertEqual(self.get("/v1/containers?all=1&all=0")[0], 400)
            self.assertEqual(self.get("/v1/containers?format=labels")[0], 400)
            self.assertEqual(self.get("/v1/sources/outside/lines")[0], 404)
            cli.write_text("#!/bin/sh\nprintf 'secret Docker error\\n' >&2\nexit 1\n")
            self.assertEqual(self.get("/v1/containers"), (502, {"error": "source_unavailable"}))

    def mcp(self, method, params=None, *, token=TOKEN, use_path=False, headers=None, notify=False):
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   **(headers or {})}
        path = f"/t/{TOKEN.decode()}/mcp" if use_path else "/mcp"
        if token is not None and not use_path:
            headers["Authorization"] = "Bearer " + token.decode()
        message = {"jsonrpc": "2.0", "method": method}
        if not notify:
            message["id"] = 7
        if params is not None:
            message["params"] = params
        conn = http.client.HTTPConnection(*self.sock.server_address, timeout=3)
        try:
            conn.request("POST", path, body=json.dumps(message), headers=headers)
            res = conn.getresponse()
            data = res.read()
            return res.status, json.loads(data) if data else None
        finally:
            conn.close()

    def test_mcp_handshake_discovery_and_read_only_tools(self):
        status, init = self.mcp("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"},
        })
        self.assertEqual((status, init["id"], init["result"]["protocolVersion"]), (200, 7, "2025-06-18"))
        self.assertEqual(self.mcp("notifications/initialized", use_path=True, notify=True), (202, None))
        tools = self.mcp("tools/list", use_path=True)[1]["result"]["tools"]
        self.assertEqual({t["name"] for t in tools}, {"list_containers", "list_log_sources", "read_logs"})
        self.assertTrue(all(t["annotations"]["readOnlyHint"] for t in tools))
        sources = self.mcp("tools/call", {"name": "list_log_sources"}, use_path=True)[1]["result"]["structuredContent"]
        self.assertEqual(sources["sources"][0], {"id": "file", "kind": "file"})
        with patch.object(server, "list_containers", return_value=[]) as inventory:
            self.mcp("tools/call", {"name": "list_containers", "arguments": {"all": True}}, use_path=True)
            inventory.assert_called_once_with(True)
        data = self.mcp("tools/call", {
            "name": "read_logs", "arguments": {"source_id": "file", "mode": "tail", "limit": 1},
        }, use_path=True)[1]["result"]["structuredContent"]
        self.assertEqual(data["lines"], ["last"])
        for args in ({"source_id": "/etc/passwd"}, {"source_id": "file", "limit": True},
                     {"source_id": "file", "path": "/etc/passwd"}, {"source_id": "file", "offset": 1}):
            self.assertEqual(self.mcp("tools/call", {"name": "read_logs", "arguments": args})[1]["error"]["code"], -32602)
        missing = self.mcp("tools/call", {"name": "read_logs", "arguments": {"source_id": "missing"}})[1]["result"]
        self.assertTrue(missing["isError"])
        self.assertEqual(self.mcp("docker/exec")[1]["error"]["code"], -32601)

    def test_mcp_requires_auth_and_rejects_browser_origins_and_bad_versions(self):
        self.assertEqual(self.mcp("tools/list", token=None)[0], 401)
        self.assertEqual(self.mcp("tools/list", token=b"wrong")[0], 401)
        self.assertEqual(self.mcp("tools/list", use_path=True, headers={"Origin": "https://untrusted.invalid"})[0], 403)
        self.assertEqual(self.mcp("tools/list", headers={"MCP-Protocol-Version": "1990-01-01"})[0], 400)
        self.assertEqual(self.get("/mcp")[0], 405)
        self.assertEqual(self.get("/mcp", None)[0], 401)

    def test_file_rejects_symlinks_and_fifos(self):
        self.log.unlink()
        self.log.symlink_to("/etc/passwd")
        self.assertEqual(self.lines("file", "limit=1"), (502, {"error": "source_unavailable"}))
        self.log.unlink()
        os.mkfifo(self.log)
        self.assertEqual(self.lines("file", "limit=1")[0], 502)

    def test_docker_stream_both_channels_and_sanitized_failure(self):
        cli = self.dir / "docker"
        cli.write_text("""#!/bin/sh
set -eu
[ "$1,$2,$3,$4" = '--host,unix:///var/run/docker.sock,logs,--timestamps' ]
if [ "$5" = '--tail' ]; then
  [ "$6,$7,$8" = '2,--,allowed-container' ]
  printf '2026-11-25T00:00:01Z two\\n' >&2
  printf '2026-11-25T00:00:02.123456789Z three\\n'
else
  [ "$5,$6" = '--,allowed-container' ]
  printf '2026-11-25T00:00:00Z one\\n2026-11-25T00:00:01Z two\\n'
fi
""")
        cli.chmod(0o700)
        with patch.dict(os.environ, PATH=f"{self.dir}:{os.environ['PATH']}"):
            result = self.lines("docker", "limit=1&offset=1")
            self.assertEqual(result[1]["lines"], ["2026-11-25T00:00:01Z two"])
            result = self.lines("docker", "mode=tail&limit=2")
            self.assertEqual(result[1]["lines"], ["2026-11-25T00:00:01Z two", "2026-11-25T00:00:02.123456789Z three"])
            cli.write_text("#!/bin/sh\nprintf 'sensitive daemon error\\n' >&2\nexit 1\n")
            self.assertEqual(self.lines("docker", "limit=1"), (502, {"error": "source_unavailable"}))

    def test_resource_ceiling_and_config(self):
        self.log.write_bytes(b"x" * (server.MAX_OUTPUT + 1))
        self.assertEqual(self.lines("file", "limit=1")[0], 413)
        token = self.dir / "token"
        token.write_bytes(TOKEN + b"\n")
        conf = self.dir / "config.json"
        sources = [{"id": "example", "kind": "file", "path": str(self.log)}]
        conf.write_text(json.dumps({"token_file": str(token), "sources": sources}))
        self.assertEqual(server.read_config(conf), (TOKEN, {"example": ("file", str(self.log))}))
        for item in ({"id":"example","kind":"file","path":"/etc/../file"},
                     {"id":"example","kind":"docker","container":"--help"}, sources[0]):
            conf.write_text(json.dumps({"token_file": str(token), "sources": sources + [item]}))
            with self.assertRaises(ValueError):
                server.read_config(conf)

if __name__ == "__main__":
    unittest.main()
