from __future__ import annotations

import argparse
import json
import mimetypes
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from backend.view_model import load_view_state


class ViewerHandler(BaseHTTPRequestHandler):
    payload_dir: Path
    frontend_dir: Path
    logo_path: Path | None

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/assets/logo":
            if self.logo_path and self.logo_path.exists() and self.logo_path.is_file():
                self._file(self.logo_path)
                return
            self.send_error(HTTPStatus.NOT_FOUND, "Logo not found")
            return

        snapshot_key = query.get("snapshot", [None])[0]

        if path == "/api/state":
            self._json(load_view_state(self.payload_dir, snapshot_key=snapshot_key))
            return

        if path == "/api/snapshot":
            self._json(load_view_state(self.payload_dir, snapshot_key=snapshot_key).get("snapshot", {}))
            return

        if path == "/api/tables":
            self._json(load_view_state(self.payload_dir, snapshot_key=snapshot_key).get("tables", {}))
            return

        if path == "/api/meta":
            self._json(load_view_state(self.payload_dir, snapshot_key=snapshot_key).get("meta", {}))
            return

        if path in {"/", "/index.html"}:
            self._file(self.frontend_dir / "index.html")
            return

        candidate = (self.frontend_dir / path.lstrip("/")).resolve()
        if self.frontend_dir.resolve() in candidate.parents or candidate == self.frontend_dir.resolve():
            if candidate.exists() and candidate.is_file():
                self._file(candidate)
                return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def _json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path) -> None:
        body = path.read_bytes()
        content_type, _ = mimetypes.guess_type(str(path))
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args, **_kwargs) -> None:
        return


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Simple viewer for InsightVM snapshot payloads")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", type=int, default=8787, help="Port to bind")
    parser.add_argument("--payload-dir", default="payloads", help="Directory containing prepared_backend_latest.json")
    parser.add_argument("--frontend-dir", default="frontend", help="Directory containing static frontend files")
    parser.add_argument("--logo-path", default="../logo-mifibra-lp-165x74-1 (1).png", help="Logo file path to expose in the viewer")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    payload_dir = Path(args.payload_dir).resolve()
    frontend_dir = Path(args.frontend_dir).resolve()
    logo_path = Path(args.logo_path).resolve() if args.logo_path else None
    if not frontend_dir.exists():
        raise FileNotFoundError(f"Frontend directory not found: {frontend_dir}")

    handler = type(
        "ConfiguredViewerHandler",
        (ViewerHandler,),
        {
            "payload_dir": payload_dir,
            "frontend_dir": frontend_dir,
            "logo_path": logo_path,
        },
    )
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"Viewer running on http://{args.host}:{args.port}")
    print(f"Payload dir: {payload_dir}")
    print(f"Frontend dir: {frontend_dir}")
    print(f"Logo path: {logo_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
