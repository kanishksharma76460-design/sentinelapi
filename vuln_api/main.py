"""
SentinelAPI — deliberately vulnerable sandbox API (demo target).

This app is INTENTIONALLY insecure. It exists so the scanner has a deterministic
target with seeded, known vulnerability classes:

  1. BOLA / IDOR            — no object-level authorization on resource reads
                              AND writes (any token can read/update any record).
  2. Excessive data exposure — spec declares a minimal schema but responses leak
                              extra fields, including NESTED ones.
  3. Broken authentication  — the spec declares an API-key security requirement,
                              but endpoints return data with no token at all.

A SECURE control endpoint (/posts/{id}) and an ownership-checked endpoint
(/users/{id}/profile) exist so accuracy can be measured against known negatives.

Run:  uvicorn vuln_api.main:app --port 8000
"""
from __future__ import annotations

from fastapi import Body, Depends, FastAPI, Header, HTTPException
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

# The spec DECLARES that every endpoint requires an API key in the Authorization
# header. auto_error=False means FastAPI does NOT enforce it — only documents it.
# This is exactly the "declared-but-not-enforced" auth gap the scanner detects.
_api_key = APIKeyHeader(name="Authorization", auto_error=False)

app = FastAPI(
    title="Sandbox Bank API",
    description="Deliberately vulnerable API used as the SentinelAPI scan target.",
    version="1.0.0",
)


@app.middleware("http")
async def _leak_server_header(request, call_next):
    response = await call_next(request)
    response.headers["X-Powered-By"] = "SentinelBank/1.0"
    return response

# ---------------------------------------------------------------------------
# In-memory "database"
# ---------------------------------------------------------------------------
_USERS: dict[int, dict] = {}
_ORDERS: dict[int, dict] = {}
_POSTS: dict[int, dict] = {}
_ADMIN_TOKENS: set[str] = set()
_next_id = 1


class RegisterBody(BaseModel):
    username: str


# Minimal public schema DECLARED to the world (what the spec says is returned).
_USER_PUBLIC_SCHEMA = {
    "description": "User profile",
    "content": {
        "application/json": {
            "schema": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "username": {"type": "string"},
                    "email": {"type": "string"},
                },
            }
        }
    },
}

_ORDER_PUBLIC_SCHEMA = {
    "description": "Order record",
    "content": {
        "application/json": {
            "schema": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "integer"},
                    "user_id": {"type": "integer"},
                    "amount": {"type": "number"},
                },
            }
        }
    },
}

# A SECURE, correctly-implemented endpoint. It enforces ownership and returns
# exactly the declared fields. It exists so the scanner's accuracy can be
# measured against a known-negative control (must produce ZERO findings).
_POST_PUBLIC_SCHEMA = {
    "description": "Post record (secure)",
    "content": {
        "application/json": {
            "schema": {
                "type": "object",
                "properties": {
                    "post_id": {"type": "integer"},
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                },
            }
        }
    },
}

# Declares only profile.bio, but the handler returns NESTED sensitive data
# (profile.ssn, payment.card, payment.cvv) — a nested-exposure flaw.
_PROFILE_PUBLIC_SCHEMA = {
    "description": "User profile (secure)",
    "content": {
        "application/json": {
            "schema": {
                "type": "object",
                "properties": {
                    "profile": {
                        "type": "object",
                        "properties": {"bio": {"type": "string"}},
                    }
                },
            }
        }
    },
}


@app.post("/register", status_code=201)
def register(body: RegisterBody):
    """Create a user and an order; return credentials for the demo client."""
    global _next_id
    uid = _next_id
    _next_id += 1

    token = f"tok_{uid}_secret"
    if body.username == "admin":
        _ADMIN_TOKENS.add(token)

    _USERS[uid] = {
        "id": uid,
        "username": body.username,
        "email": f"{body.username}@example.com",
        "password_hash": f"$2b$12$hashof{uid}user",   # MUST never be returned
        "ssn": f"XXX-XX-{1000 + uid}",                # MUST never be returned
        "token": token,
    }
    _ORDERS[uid] = {
        "order_id": 1000 + uid,
        "user_id": uid,
        "amount": 100.0 * uid,
        "card_last4": str(4000 + uid),                # MUST never be returned
    }
    _POSTS[uid] = {
        "post_id": 5000 + uid,
        "owner_id": uid,
        "title": f"Post by {body.username}",
        "body": "hello world",
    }

    return {
        "id": uid,
        "username": body.username,
        "email": _USERS[uid]["email"],
        "token": token,
        "order_id": _ORDERS[uid]["order_id"],
        "post_id": _POSTS[uid]["post_id"],
    }


@app.get("/users/{user_id}", responses={200: _USER_PUBLIC_SCHEMA}, dependencies=[Depends(_api_key)])
def get_user(user_id: int, authorization: str = Header(default="")):
    """
    FLAW 1 (IDOR): no check that the caller owns `user_id`.
    FLAW 2 (exposure): returns password_hash / ssn / token that the spec hides.
    """
    user = _USERS.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    return user  # leaks the whole dict, including fields absent from the schema


@app.get("/orders/{order_id}", responses={200: _ORDER_PUBLIC_SCHEMA}, dependencies=[Depends(_api_key)])
def get_order(order_id: int, authorization: str = Header(default="")):
    """
    FLAW 3 (IDOR): no check that the caller owns `order_id`.
    FLAW 4 (exposure): returns card_last4 that the spec hides.
    """
    for order in _ORDERS.values():
        if order["order_id"] == order_id:
            return order
    raise HTTPException(status_code=404, detail="order not found")


@app.get("/posts/{post_id}", responses={200: _POST_PUBLIC_SCHEMA}, dependencies=[Depends(_api_key)])
def get_post(post_id: int, authorization: str = Header(default="")):
    """SECURE control: ownership is enforced and only declared fields are returned."""
    token = authorization.removeprefix("Bearer ")
    for post in _POSTS.values():
        if post["post_id"] == post_id:
            if _USERS[post["owner_id"]]["token"] != token:
                raise HTTPException(status_code=403, detail="forbidden")
            return {"post_id": post["post_id"], "title": post["title"], "body": post["body"]}
    raise HTTPException(status_code=404, detail="post not found")


@app.put("/users/{user_id}", responses={200: _USER_PUBLIC_SCHEMA}, dependencies=[Depends(_api_key)])
def update_user(user_id: int, authorization: str = Header(default=""), body: dict | None = Body(default=None)):
    """
    FLAW: no ownership check on WRITE — any token can update any user's record.
    Also returns the full record (exposure) and needs no auth at all.
    """
    user = _USERS.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    return user  # body accepted but ignored (no mass-assignment here)


@app.get("/users/{user_id}/profile", responses={200: _PROFILE_PUBLIC_SCHEMA}, dependencies=[Depends(_api_key)])
def get_profile(user_id: int, authorization: str = Header(default="")):
    """
    SECURE ownership check, but leaks NESTED sensitive data that the schema hides.
    """
    token = authorization.removeprefix("Bearer ")
    user = _USERS.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    if user["token"] != token:
        raise HTTPException(status_code=403, detail="forbidden")
    return {
        "profile": {
            "bio": f"hello from {user['username']}",
            "ssn": user["ssn"],                        # nested leak (absent from schema)
        },
        "payment": {                                    # whole subtree absent from schema
            "card": _ORDERS[user_id]["card_last4"],
            "cvv": "123",
        },
    }


@app.get("/admin/users", dependencies=[Depends(_api_key)])
def admin_users():
    """
    FLAW: broken authentication — should be admin-only, but returns everyone's
    PII with no authentication whatsoever.
    """
    return {
        "users": [
            {"id": u["id"], "username": u.get("username"), "email": u.get("email"), "ssn": u.get("ssn")}
            for u in _USERS.values()
        ]
    }


@app.get("/admin/stats", dependencies=[Depends(_api_key)])
def admin_stats(authorization: str = Header(default="")):
    """SECURE control: only admin tokens may access stats."""
    token = authorization.removeprefix("Bearer ")
    if token not in _ADMIN_TOKENS:
        raise HTTPException(status_code=403, detail="forbidden")
    return {"total_users": len(_USERS), "total_orders": len(_ORDERS)}


@app.post("/users", status_code=201, dependencies=[Depends(_api_key)])
def create_user(body: dict = Body(default={}), authorization: str = Header(default="")):
    """FLAW: mass assignment — arbitrary fields (role, is_admin) are stored."""
    token = authorization.removeprefix("Bearer ")
    if not any(u.get("token") == token for u in _USERS.values()):
        raise HTTPException(status_code=403, detail="forbidden")
    global _next_id
    uid = _next_id
    _next_id += 1
    username = body.get("username", "anon")
    user = {
        "id": uid,
        "username": username,
        "email": f"{username}@example.com",
        "ssn": f"XXX-XX-{1000 + uid}",
        "token": f"tok_{uid}_secret",
    }
    user.update(body)  # mass assignment: copies every supplied field, incl. role/is_admin
    _USERS[uid] = user
    return user


@app.get("/debug", include_in_schema=False)
def debug_info():
    """FLAW: exposed debug endpoint (improper inventory) — leaks internal config."""
    return {
        "debug": True,
        "environment": "production",
        "app_version": "1.0.0",
        "secret_key": "sk_live_9f8e7d6c5b4a3210",
        "config": {"db_host": "internal-db:5432", "debug_mode": True},
    }


@app.get("/health")
def health():
    return {"status": "ok"}
