"""零依赖 HTTP 服务：页面 + 真实分析/处置 API + 健康路径。

环境变量：
  HOST  绑定地址（默认 0.0.0.0）
  PORT  宿主端口（默认 8080，可配置）
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .store import Store
from .validate import PayloadError, SourceMissing

STORE = Store()

with open(os.path.join(os.path.dirname(__file__), "static", "index.html"),
          "r", encoding="utf-8") as _f:
    INDEX_HTML = _f.read()


def _payload_errors(exc: PayloadError) -> list[str]:
    errs = exc.args[0] if exc.args else ["无效载荷"]
    if isinstance(errs, (list, tuple)):
        return [str(e) for e in errs]
    return [str(errs)]


class Handler(BaseHTTPRequestHandler):
    server_version = "RailAudit/1.0"

    def log_message(self, fmt, *args):  # 安静些
        pass

    def _send_json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._send_json(200, {"status": "ok", "service": "rail-emergency-audit"})
            return
        if path in ("/", "/index.html"):
            body = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path.startswith("/api/evidence/"):
            audit_id = path[len("/api/evidence/"):]
            rec = STORE.get(audit_id)
            if rec is None:
                self._send_json(404, {"error": f"无审计标识 {audit_id} 的冻结证据"})
            else:
                self._send_json(200, rec)
            return
        if path.startswith("/api/disposal/"):
            disposal_id = path[len("/api/disposal/"):]
            rec = STORE.get_disposal(disposal_id)
            if rec is None:
                self._send_json(404, {"error": f"无处置标识 {disposal_id} 的冻结方案"})
            else:
                self._send_json(200, rec)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path not in ("/api/analyze", "/api/dispose"):
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError) as exc:
            self._send_json(400, {"ok": False, "errors": [f"请求不是合法 JSON: {exc}"]})
            return

        if path == "/api/analyze":
            try:
                result, errors, conflict = STORE.analyze(payload)
            except PayloadError as exc:
                self._send_json(400, {"ok": False, "errors": _payload_errors(exc)})
                return
            if conflict is not None:
                self._send_json(409, {"ok": False, "conflict": conflict})
                return
            self._send_json(200, {"ok": True, "result": result})
            return

        # /api/dispose：对已冻结的危险可达审计确认最低处置代价
        try:
            result, conflict = STORE.dispose(payload)
        except SourceMissing as exc:
            self._send_json(404, {"ok": False, "error": str(exc)})
            return
        except PayloadError as exc:
            self._send_json(400, {"ok": False, "errors": _payload_errors(exc)})
            return
        if conflict is not None:
            self._send_json(409, {"ok": False, "conflict": conflict})
            return
        self._send_json(200, {"ok": True, "result": result})


def build_server(host: str, port: int) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    return httpd


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    httpd = build_server(host, port)
    print(f"rail-emergency-audit listening on http://{host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
