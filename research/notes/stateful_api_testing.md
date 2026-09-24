# Stateful API Testing

## Core idea

APIs are state machines. A `GET /users/{id}` only makes sense after a `POST /register` or `POST /users`. A scanner that ignores ordering will miss deeper bugs.

## Key concepts

- **Producer-consumer dependencies.** Endpoint A produces a value; endpoint B consumes it.
- **Resource lifecycle.** Create → Read → Update → Delete sequences expose missing authz on write/delete.
- **State reset.** Each scan run must start from a clean state to stay deterministic.

## Relevant work

- **RESTler** — builds a dependency graph dynamically and uses it to drive stateful sequences.
- **EvoMaster** — handles stateful sequences with evolutionary algorithms.
- **Morest** — explicit state-machine model.
- **Bandago** / **ARVADA** — automata learning for stateful systems.

## Takeaway for SentinelAPI

The current scanner knows only `/register`. Generalise to:

1. **Dependency graph from spec.** Map path parameters to response fields.
2. **CRUD lifecycle tests.** For every resource, run create/read/update/delete under A and B tokens and swap IDs at each step.
3. **State isolation.** Provide a `/reset` endpoint in `vuln_api` or restart the API per scan run.

## Prototype path

- Add `scanner/dependency.py` with graph construction.
- Add `scanner/lifecycle.py` with CRUD workflows.
- Extend `vuln_api/main.py` with a privileged `/reset` endpoint for clean demos.
