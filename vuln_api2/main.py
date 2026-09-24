"""
SentinelAPI — second vulnerable sandbox target ("Library API").

A different API shape than vuln_api, used to prove the scanner generalises
beyond a single hardcoded target: its identifiers (book_id, member_id) differ
from the Bank API's (order_id, post_id), which the scanner must infer
generically from the /register response.

Seeded flaws:
  1. BOLA / IDOR            — /books/{book_id}: no ownership check (any token
                              reads any book).
  2. Excessive data exposure — /books/{book_id} returns isbn (undeclared);
                              /members/{member_id}/profile returns nested
                              member.library_card (undeclared).
  3. Broken authentication  — /books/{book_id} and /members declare security
                              but return data with no token.
Secure control: /members/{member_id}/profile enforces ownership.

Run:  uvicorn vuln_api2.main:app --port 8000
"""
from __future__ import annotations

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

_api_key = APIKeyHeader(name="Authorization", auto_error=False)

app = FastAPI(
    title="Sandbox Library API",
    description="Second deliberately vulnerable API used as a benchmark target.",
    version="1.0.0",
)


@app.middleware("http")
async def _leak_server_header(request, call_next):
    response = await call_next(request)
    response.headers["X-Powered-By"] = "LibraryService/2.4"
    return response

_USERS: dict[int, dict] = {}
_BOOKS: dict[int, dict] = {}
_MEMBERS: dict[int, dict] = {}
_next_id = 1


class RegisterBody(BaseModel):
    username: str


_BOOK_SCHEMA = {
    "description": "Book record",
    "content": {"application/json": {"schema": {"type": "object", "properties": {
        "book_id": {"type": "integer"},
        "title": {"type": "string"},
        "author": {"type": "string"},
        "owner_id": {"type": "integer"},
    }}}},
}

_PROFILE_SCHEMA = {
    "description": "Member profile (secure)",
    "content": {"application/json": {"schema": {"type": "object", "properties": {
        "member": {"type": "object", "properties": {"name": {"type": "string"}}},
    }}}},
}


@app.post("/register", status_code=201)
def register(body: RegisterBody):
    global _next_id
    uid = _next_id
    _next_id += 1
    token = f"libtok_{uid}"
    _USERS[uid] = {
        "id": uid, "username": body.username,
        "email": f"{body.username}@lib.org", "token": token,
    }
    _BOOKS[uid] = {
        "book_id": 7000 + uid, "title": f"Book {uid}", "author": f"Author {uid}",
        "owner_id": uid, "isbn": f"978-3-16-{uid}",  # MUST never be returned
    }
    _MEMBERS[uid] = {
        "member_id": 9000 + uid, "owner_id": uid,
        "name": f"{body.username} reader",
        "library_card": f"LC-{uid}",  # MUST never be returned
    }
    return {
        "id": uid, "username": body.username, "email": _USERS[uid]["email"],
        "token": token, "book_id": 7000 + uid, "member_id": 9000 + uid,
    }


@app.get("/books/{book_id}", responses={200: _BOOK_SCHEMA}, dependencies=[Depends(_api_key)])
def get_book(book_id: int, authorization: str = Header(default="")):
    """FLAW: BOLA (no ownership check) + exposure (isbn) + no auth enforcement."""
    for book in _BOOKS.values():
        if book["book_id"] == book_id:
            return book
    raise HTTPException(status_code=404, detail="book not found")


@app.get("/members", dependencies=[Depends(_api_key)])
def list_members():
    """FLAW: broken authentication — returns member PII with no auth."""
    return {
        "members": [
            {"member_id": m["member_id"], "name": m["name"], "library_card": m["library_card"]}
            for m in _MEMBERS.values()
        ]
    }


@app.get("/members/{member_id}/profile", responses={200: _PROFILE_SCHEMA}, dependencies=[Depends(_api_key)])
def member_profile(member_id: int, authorization: str = Header(default="")):
    """SECURE ownership check, but leaks nested member.library_card."""
    token = authorization.removeprefix("Bearer ")
    for m in _MEMBERS.values():
        if m["member_id"] == member_id:
            if _USERS[m["owner_id"]]["token"] != token:
                raise HTTPException(status_code=403, detail="forbidden")
            return {"member": {"name": m["name"], "library_card": m["library_card"]}}
    raise HTTPException(status_code=404, detail="member not found")


@app.get("/debug", include_in_schema=False)
def debug_info():
    """FLAW: exposed debug endpoint (improper inventory) — leaks internal config."""
    return {
        "debug": True,
        "environment": "production",
        "app_version": "2.4.0",
        "secret_key": "lib_secret_0123456789abcdef",
        "config": {"db_host": "library-db:5432", "debug_mode": True},
    }


@app.get("/health")
def health():
    return {"status": "ok"}
