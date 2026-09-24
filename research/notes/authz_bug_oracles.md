# Authorization Bug Oracles

## Core idea

Authorization bugs (BOLA/IDOR) are detected by **comparing behavior across security contexts**. The oracle is the difference, not a single response.

## Oracles in the literature

| Oracle | How it works | Best for |
|---|---|---|
| Cross-account differential | Same request with two user tokens | BOLA on read endpoints |
| Role differential | Admin vs user vs unauthenticated | Missing function-level checks |
| Response invariants | User A should never see User B's PII | Semantic leaks |
| Status-code agreement | 404 vs 403 leakage | Information disclosure |

## Important nuance: 200 vs 403

A server returning `200 OK` with another user's data is an obvious bug. But returning `404` when unauthorized and `200` when authorized is *not* a bug — it is a safe pattern. The oracle must look at **content**, not status code alone.

## Relevant work

- **NoSQL/IDOR academic surveys** — "broken object-level authorization" is now the #1 OWASP API Security risk.
- **Authz** tools like **AuthMatrix**, **AutoRize**, **BOLA-Rebel** (where available) automate the role-context matrix.

## Takeaway for SentinelAPI

Current code already does cross-account differential testing for `GET`. Extend it to:

1. Build an **auth-context matrix**: `none`, `A`, `B`, `A_wrong_token`, `B_expired_token`.
2. Apply it to **all HTTP methods**, not just `GET`.
3. Add an oracle that checks whether identifiers belonging to another principal appear **anywhere** in the response (already partially implemented with `contains_value`).
4. Flag **semantic leaks**: e.g. `email`, `ssn`, or `card_last4` from another user even if the `id` does not match.

## Prototype path

- Add `AuthContext` dataclass and a matrix runner.
- Generalise `check_bola` to accept arbitrary methods and a list of tokens.
- Add a `should_never_see` oracle that scans for foreign principal markers in any response field.
