import collections
import contextlib
import hmac
import json
import os
import re
import selectors
import stat
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, urlsplit

MAX_LIMIT = 1000
MAX_OFFSET = 1_000_000
MAX_SCAN = 64 * 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024
BLOCK = 64 * 1024
TIMEOUT = 12
ID_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
PATH_TOKEN_RE = re.compile(r"[A-Za-z0-9_.~-]{32,256}")
TIMESTAMP_RE = re.compile(rb"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z ")

class ReadError(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code

def read_config(path):
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(config, dict) or set(config) != {"token_file", "sources"}:
        raise ValueError("expected token_file and sources")
    token = Path(config["token_file"]).read_bytes().strip()
    if not re.fullmatch(rb"[A-Za-z0-9_.~+/-]{32,256}={0,2}", token):
        raise ValueError("token must contain at least 32 valid bearer-token characters")
    sources = {}
    if not isinstance(config["sources"], list) or not config["sources"]:
        raise ValueError("sources must be a nonempty array")
    for item in config["sources"]:
        if not isinstance(item, dict):
            raise ValueError("invalid source")
        source_id = item.get("id")
        kind = item.get("kind")
        fields = {"docker": "container", "file": "path"}
        if (not isinstance(source_id, str) or not ID_RE.fullmatch(source_id)
                or source_id in sources or not isinstance(kind, str) or kind not in fields):
            raise ValueError("invalid or duplicate source ID, or unknown kind")
        field = fields[kind]
        value = item.get(field)
        if set(item) != {"id", "kind", field} or not isinstance(value, str):
            raise ValueError("invalid source fields")
        if kind == "docker" and not ID_RE.fullmatch(value):
            raise ValueError("invalid container name")
        if kind == "file":
            p = PurePosixPath(value)
            if not p.is_absolute() or ".." in p.parts or len(p.parts) < 2:
                raise ValueError("file source requires an absolute file path without '..'")
        sources[source_id] = (kind, value)
    return token, sources

def parameters(query):
    settings = parse_qs(query, keep_blank_values=True, max_num_fields=3)
    if any(k not in {"mode", "offset", "limit"} or len(v) != 1 for k, v in settings.items()):
        raise ValueError()
    mode = settings.get("mode", ["head"])[0]
    if mode not in {"head", "tail"} or (mode == "tail" and "offset" in settings):
        raise ValueError()
    def number(key, default, lo, hi):
        raw = settings.get(key, [default])[0]
        if not re.fullmatch(r"[0-9]{1,7}", raw) or not lo <= int(raw) <= hi:
            raise ValueError()
        return int(raw)
    return mode, number("offset", "0", 0, MAX_OFFSET), number("limit", "1000", 1, MAX_LIMIT)

@contextlib.contextmanager
def regular_file(path):
    parts = PurePosixPath(path).parts
    if len(parts) < 2:
        raise ReadError(502, "source_unavailable")
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with contextlib.ExitStack() as stack:
        fd = os.open("/", dir_flags)
        stack.callback(os.close, fd)
        for part in parts[1:-1]:
            fd = os.open(part, dir_flags, dir_fd=fd)
            stack.callback(os.close, fd)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        stack.callback(os.close, fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ReadError(502, "source_unavailable")
        yield fd, info.st_size

def distance_too_large():
    return ReadError(413, "read_limit_exceeded")

def file_chunks(fd, size, deadline):
    for start in range(0, size, BLOCK):
        if time.monotonic() >= deadline:
            raise ReadError(504, "source_timeout")
        yield os.pread(fd, min(BLOCK, size - start), start)

def from_tail(fd, size, limit, deadline):
    chunks = collections.deque()
    count = 0
    end = size
    while end and count <= limit:
        if time.monotonic() >= deadline:
            raise ReadError(504, "source_timeout")
        start = max(0, end - BLOCK)
        if size - start > MAX_SCAN:
            raise distance_too_large()
        chunk = os.pread(fd, end - start, start)
        chunks.appendleft(chunk)
        count += chunk.count(b"\n")
        end = start
    return b"".join(chunks)

def whole_lines(chunks, deadline):
    partial = b""
    scanned = 0
    for chunk in chunks:
        if time.monotonic() >= deadline:
            raise ReadError(504, "source_timeout")
        scanned += len(chunk)
        if scanned > MAX_SCAN:
            raise distance_too_large()
        *rows, partial = (partial + chunk).split(b"\n")
        if len(partial) > MAX_OUTPUT:
            raise distance_too_large()
        yield from rows
    if partial:
        yield partial

@contextlib.contextmanager
def docker_chunks(name, mode, limit, deadline):
    args = ["docker", "--host", "unix:///var/run/docker.sock", "logs", "--timestamps"]
    if mode == "tail":
        args.extend(("--tail", str(limit)))
    args.extend(("--", name))
    with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT) as process:
        def read():
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    left = deadline - time.monotonic()
                    if left <= 0 or not selector.select(left):
                        raise ReadError(504, "source_timeout")
                    chunk = os.read(process.stdout.fileno(), BLOCK)
                    if not chunk:
                        break
                    yield chunk
            try:
                status = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise ReadError(504, "source_timeout") from None
            if status:
                raise ReadError(502, "source_unavailable")
        try:
            yield read()
        finally:
            if process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()

def collect(rows, offset, limit, docker=False):
    result = []
    output_bytes = 0
    for index, row in enumerate(rows):
        if docker and not TIMESTAMP_RE.match(row):
            raise ReadError(502, "source_unavailable")
        if index < offset:
            continue
        decoded = row.removesuffix(b"\r").decode("utf-8", "replace")
        output_bytes += len(json.dumps(decoded, ensure_ascii=False).encode("utf-8")) + 1
        if output_bytes > MAX_OUTPUT:
            raise distance_too_large()
        result.append(decoded)
        if len(result) == limit:
            break
    return result

def read_source(source, mode, offset, limit):
    kind, value = source
    deadline = time.monotonic() + TIMEOUT
    try:
        if kind == "file":
            with regular_file(value) as (fd, size):
                if mode == "head":
                    return collect(whole_lines(file_chunks(fd, size, deadline), deadline), offset, limit)
                data = from_tail(fd, size, limit, deadline).removesuffix(b"\n")
                if not data and size == 0:
                    return []
                return collect(data.rsplit(b"\n", limit)[-limit:], 0, limit)
        with docker_chunks(value, mode, limit, deadline) as chunks:
            rows = whole_lines(chunks, deadline)
            if mode == "head":
                return collect(rows, offset, limit, docker=True)
            # Consume through EOF for tail so daemon errors cannot become a success.
            retained = collections.deque(maxlen=limit)
            retained_bytes = 0
            for row in rows:
                if not TIMESTAMP_RE.match(row):
                    raise ReadError(502, "source_unavailable")
                if len(retained) == limit:
                    retained_bytes -= len(retained[0])
                retained_bytes += len(row)
                if retained_bytes > MAX_OUTPUT:
                    raise distance_too_large()
                retained.append(row)
            return collect(retained, 0, limit)
    except OSError:
        raise ReadError(502, "source_unavailable") from None

class Server(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, token, sources):
        self.token, self.sources = token, sources
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(address, Handler)

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(5)
        return sock, addr

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # Do not put request paths, credentials or local file names in logs.
        print("Log API request failed.", flush=True)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond(self, status, body):
        content = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(content)))
        if status == 401:
            self.send_header("WWW-Authenticate", "Bearer")
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        try:
            if len(self.path) > 1024:
                raise ValueError()
            uri = urlsplit(self.path)
            if uri.scheme or uri.netloc or uri.fragment:
                raise ValueError()
            path = uri.path
            if path.startswith("/t/"):
                key, sep, rest = path[3:].partition("/")
                allowed = bool(sep and PATH_TOKEN_RE.fullmatch(key)
                               and hmac.compare_digest(key.encode("ascii"), self.server.token))
                path = "/" + rest
            else:
                headers = self.headers.get_all("Authorization", [])
                expected = b"Bearer " + self.server.token
                allowed = len(headers) == 1 and hmac.compare_digest(headers[0].encode("latin-1"), expected)
            if not allowed:
                return self.respond(401, {"error": "unauthorized"})
            if path == "/v1/sources" and not uri.query:
                return self.respond(200, {"sources": [
                    {"id": sid, "kind": spec[0]} for sid, spec in self.server.sources.items()
                ]})
            match = re.fullmatch(r"/v1/sources/([a-zA-Z0-9_.-]+)/lines", path)
            if not match or match[1] not in self.server.sources:
                return self.respond(404, {"error": "source_not_found"})
            mode, offset, limit = parameters(uri.query)
            lines = read_source(self.server.sources[match[1]], mode, offset, limit)
            return self.respond(200, {"id": match[1], "mode": mode, "offset": offset if mode == "head" else None,
                                      "lines": lines})
        except ValueError:
            return self.respond(400, {"error": "invalid_request"})
        except ReadError as exc:
            return self.respond(exc.status, {"error": exc.code})

if __name__ == "__main__":
    try:
        token, sources = read_config(os.environ.get("LOG_API_CONFIG", "/config/config.json"))
    except (OSError, KeyError, ValueError, TypeError):
        raise SystemExit("Cannot read valid log API configuration or token file.")
    with Server(("0.0.0.0", 8080), token, sources) as server:
        print("Log API listening on port 8080.", flush=True)
        server.serve_forever()
