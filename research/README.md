# SentinelAPI Research Track

Goal: upgrade the current demo scanner from a classroom-grade BOLA + exposure detector to a state-of-the-art API vulnerability scanner.

The current baseline is a **dynamic differential tester**: it registers two users, swaps identifiers, and diffs response keys against the OpenAPI schema. That is already the correct *shape* of modern APIsec work, but it is shallow on auth state exploration, dependency ordering, and oracle depth.

This directory collects the ideas and papers that justify each upgrade.

---

## Research axes

| Axis | Why it matters for SentinelAPI | See |
|---|---|---|
| OpenAPI-aware test generation | Turn a spec into valid, high-coverage request sequences | `notes/openapi_test_generation.md` |
| Authorization / BOLA detection | The core demo finding; academic work has mature oracles | `notes/authz_bug_oracles.md` |
| REST API fuzzing | How to mutate requests without drowning in 400s | `notes/rest_fuzzing.md` |
| LLM-assisted security testing | Use LLMs to infer auth logic and generate edge cases | `notes/llm_security_testing.md` |
| Stateful / dependency-aware scanning | APIs are state machines, not a bag of endpoints | `notes/stateful_api_testing.md` |
| Response-schema oracles | Better ways to detect excessive exposure than key-name heuristics | `notes/schema_oracles.md` |

---

## Concrete SOTA roadmap (prioritised)

### Phase 1 — smarter than the baseline (this week)
1. **Spec-driven stateful sequences.** Parse dependencies (`POST /users` before `GET /users/{id}`) and generate valid workflows instead of registering users manually.
2. **Auth-context matrix.** Test every endpoint under `none`, `user_A`, `user_B`, `admin`, and swap tokens/resource IDs systematically.
3. **Semantic exposure oracle.** Compare response shapes to schema *recursively* and flag sensitive types (`email`, `hash`, `ssn`, `token`, `last4`, etc.) even when nested.

### Phase 2 — research-grade additions
1. **Shadow-token differential testing.** Issue multiple tokens for the same user and check if one leaks into another (session handling bugs).
2. **Role lattice fuzzing.** Brute-force subset inclusion of role claims / scopes and find endpoints that ignore privilege bits.
3. **Sequence-aware BOLA.** Chain calls: `A` creates a resource, then `B` tries `PUT /resources/{id}` and `DELETE /resources/{id}`, not only `GET`.
4. **Side-channel exposure.** Compare response times and error verbosity across auth contexts.

### Phase 3 — publication / deep-tech ceiling
1. **Hybrid static-dynamic engine.** Combine OpenAPI spec analysis with runtime feedback to refine an API dependency graph.
2. **LLM oracle for business-logic leaks.** Ask a model whether a response to a given principal is semantically appropriate.
3. **Benchmark suite.** Build a labeled corpus of vulnerable sandbox APIs (like your FastAPI target) and report precision/recall against it.

---

## How to use this folder

- `papers/` — store PDFs and BibTeX entries.
- `notes/` — short summaries with actionable takeaways for the codebase.
- Add a new note when you find a relevant paper, tool, or idea; link it above.
