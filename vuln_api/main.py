"""
SentinelAPI — deliberately vulnerable sandbox API (demo target).

This app is INTENTIONALLY insecure. It exists so the scanner has a deterministic
target with seeded, known vulnerabilities:

  1. BOLA / IDOR            — /users/{user_id} and /orders/{order_id} perform no
                              object-level authorization: any authenticated
                              token can read any user's / order's record.
  2. Excessive data exposure — the OpenAPI spec *declares* a minimal schema
                              (id, username, email) but the endpoints return
                              extra sensitive fields (password_hash, ssn, token,
                              card_last4). The scanner detects the mismatch.

Run:  uvicorn vuln_api.main:app --port 8000
"""
from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="Sandbox Bank API",
    description="Deliberately vulnerable API used as the SentinelAPI scan target.",
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# In-memory "database"
# ---------------------------------------------------------------------------
_USERS: dict[int, dict] = {}
_ORDERS: dict[int, dict] = {}
_POSTS: dict[int, dict] = {}
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


@app.post("/register", status_code=201)
def register(body: RegisterBody):
    """Create a user and an order; return credentials for the demo client."""
    global _next_id
    uid = _next_id
    _next_id += 1

    token = f"tok_{uid}_secret"

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


@app.get("/users/{user_id}", responses={200: _USER_PUBLIC_SCHEMA})
def get_user(user_id: int, authorization: str = Header(default="")):
    """
    FLAW 1 (IDOR): no check that the caller owns `user_id`.
    FLAW 2 (exposure): returns password_hash / ssn / token that the spec hides.
    """
    user = _USERS.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    return user  # leaks the whole dict, including fields absent from the schema


@app.get("/orders/{order_id}", responses={200: _ORDER_PUBLIC_SCHEMA})
def get_order(order_id: int, authorization: str = Header(default="")):
    """
    FLAW 3 (IDOR): no check that the caller owns `order_id`.
    FLAW 4 (exposure): returns card_last4 that the spec hides.
    """
    for order in _ORDERS.values():
        if order["order_id"] == order_id:
            return order
    raise HTTPException(status_code=404, detail="order not found")


@app.get("/posts/{post_id}", responses={200: _POST_PUBLIC_SCHEMA})
def get_post(post_id: int, authorization: str = Header(default="")):
    """SECURE control: ownership is enforced and only declared fields are returned."""
    token = authorization.removeprefix("Bearer ")
    for post in _POSTS.values():
        if post["post_id"] == post_id:
            if _USERS[post["owner_id"]]["token"] != token:
                raise HTTPException(status_code=403, detail="forbidden")
            return {"post_id": post["post_id"], "title": post["title"], "body": post["body"]}
    raise HTTPException(status_code=404, detail="post not found")


@app.get("/health")
def health():
    return {"status": "ok"}
