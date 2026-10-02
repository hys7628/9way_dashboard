"""우리 반 강점 보드 — 이름과 9WAY 강점 평가 링크를 모아 두는 작은 웹앱.

내 컴퓨터에서는 표준 라이브러리와 SQLite 파일만으로 돈다. 실행: python3 app.py
DATABASE_URL 환경 변수가 있으면(Render 배포) SQLite 대신 Postgres에 저장한다.
WSGI 진입점은 `application` 이다.
"""

import json
import os
import re
import secrets
import socket
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import urlsplit
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("BOARD_DB", BASE_DIR / "board.db"))
DATABASE_URL = os.environ.get("DATABASE_URL")
PORT = int(os.environ.get("PORT", "8090"))

ALLOWED_HOSTS = {"9way.co.kr", "www.9way.co.kr"}
MAX_NAME = 20
MAX_URL = 500
MAX_BODY = 4096


if DATABASE_URL:
    import psycopg
    from psycopg.rows import dict_row

    DUPLICATE_ERRORS = (psycopg.errors.UniqueViolation,)
    ID_COLUMN = "id SERIAL PRIMARY KEY"
else:
    DUPLICATE_ERRORS = (sqlite3.IntegrityError,)
    ID_COLUMN = "id INTEGER PRIMARY KEY AUTOINCREMENT"


def run(sql, params=()):
    """SQL 한 문장을 실행하고 결과 행을 dict 목록으로 돌려준다. 자리표시자는 ? 로 쓴다."""
    if DATABASE_URL:
        with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
            cur = conn.execute(sql.replace("?", "%s"), params)
            return cur.fetchall() if cur.description else []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            return [dict(row) for row in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def init_db():
    run(
        f"""
        CREATE TABLE IF NOT EXISTS members (
            {ID_COLUMN},
            name TEXT NOT NULL,
            url TEXT NOT NULL UNIQUE,
            token TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )


def clean_name(raw):
    name = re.sub(r"\s+", " ", str(raw or "")).strip()
    if not name:
        raise ValueError("이름을 입력해 주세요.")
    if len(name) > MAX_NAME:
        raise ValueError(f"이름은 {MAX_NAME}자 이내로 입력해 주세요.")
    return name


def clean_url(raw):
    url = str(raw or "").strip()
    if not url:
        raise ValueError("강점 진단 링크를 붙여 넣어 주세요.")
    if len(url) > MAX_URL or re.search(r"\s", url):
        raise ValueError("링크 형식이 올바르지 않습니다. 주소 전체를 그대로 붙여 넣어 주세요.")
    parts = urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "").lower() not in ALLOWED_HOSTS:
        raise ValueError("https://9way.co.kr 로 시작하는 강점 진단 링크만 등록할 수 있습니다.")
    return url


def respond(start_response, status, body, content_type="application/json; charset=utf-8"):
    if not isinstance(body, bytes):
        body = json.dumps(body, ensure_ascii=False).encode("utf-8")
    start_response(
        status,
        [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
        ],
    )
    return [body]


def error(start_response, status, message):
    return respond(start_response, status, {"error": message})


def list_members(start_response):
    rows = run("SELECT id, name, url, created_at FROM members ORDER BY LOWER(name), id")
    return respond(start_response, "200 OK", {"members": rows})


def add_member(environ, start_response):
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if length <= 0 or length > MAX_BODY:
        return error(start_response, "400 Bad Request", "요청 내용을 읽을 수 없습니다.")
    try:
        payload = json.loads(environ["wsgi.input"].read(length).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("요청 내용을 읽을 수 없습니다.")
        name = clean_name(payload.get("name"))
        url = clean_url(payload.get("url"))
    except UnicodeDecodeError:
        return error(start_response, "400 Bad Request", "요청 내용을 읽을 수 없습니다.")
    except json.JSONDecodeError:
        return error(start_response, "400 Bad Request", "요청 내용을 읽을 수 없습니다.")
    except ValueError as exc:
        return error(start_response, "400 Bad Request", str(exc))

    token = secrets.token_urlsafe(24)
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        rows = run(
            "INSERT INTO members (name, url, token, created_at) VALUES (?, ?, ?, ?) RETURNING id",
            (name, url, token, created_at),
        )
        member_id = rows[0]["id"]
    except DUPLICATE_ERRORS:
        return error(start_response, "409 Conflict", "이미 등록된 링크입니다. 명단을 확인해 주세요.")
    return respond(
        start_response,
        "201 Created",
        {"id": member_id, "name": name, "url": url, "created_at": created_at, "token": token},
    )


def delete_member(environ, start_response, member_id):
    token = environ.get("HTTP_X_TOKEN", "")
    rows = run("SELECT token FROM members WHERE id = ?", (member_id,))
    if not rows:
        return error(start_response, "404 Not Found", "이미 삭제된 항목입니다.")
    if not token or not secrets.compare_digest(rows[0]["token"], token):
        return error(start_response, "403 Forbidden", "본인이 등록한 기기에서만 삭제할 수 있습니다.")
    run("DELETE FROM members WHERE id = ?", (member_id,))
    return respond(start_response, "200 OK", {"deleted": member_id})


def application(environ, start_response):
    method = environ["REQUEST_METHOD"]
    path = environ.get("PATH_INFO", "/")

    if path == "/" and method == "GET":
        html = (BASE_DIR / "index.html").read_bytes()
        return respond(start_response, "200 OK", html, "text/html; charset=utf-8")
    if path == "/api/members":
        if method == "GET":
            return list_members(start_response)
        if method == "POST":
            return add_member(environ, start_response)
        return error(start_response, "405 Method Not Allowed", "지원하지 않는 요청입니다.")
    match = re.fullmatch(r"/api/members/(\d+)", path)
    if match:
        if method == "DELETE":
            return delete_member(environ, start_response, int(match.group(1)))
        return error(start_response, "405 Method Not Allowed", "지원하지 않는 요청입니다.")
    return error(start_response, "404 Not Found", "페이지를 찾을 수 없습니다.")


init_db()


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class QuietHandler(WSGIRequestHandler):
    def address_string(self):
        # 기본 구현의 역방향 DNS 조회는 교실 와이파이에서 응답을 느리게 만든다.
        return self.client_address[0]


def lan_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("10.255.255.255", 1))
            return sock.getsockname()[0]
    except OSError:
        return None


if __name__ == "__main__":
    with make_server("0.0.0.0", PORT, application, ThreadingWSGIServer, QuietHandler) as server:
        print(f"내 컴퓨터에서 열기:      http://localhost:{PORT}")
        ip = lan_ip()
        if ip:
            print(f"같은 와이파이에서 열기:  http://{ip}:{PORT}")
        server.serve_forever()
