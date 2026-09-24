# OpenAPI-Aware Test Generation

## Core idea

An OpenAPI spec is not just documentation — it is a grammar for valid requests. Treat it as a constraint system and generate request sequences that maximize coverage of paths, parameters, and response codes.

## Key concepts

- **Parameter enumeration.** Generate values for path/query/header/body parameters, respecting declared types and formats.
- **Example harvesting.** Use `example` and `examples` fields from the spec; they are high-fidelity seeds.
- **Dependency extraction.** Identify producer-consumer relationships: an endpoint returns an `id` that another endpoint consumes.
- **Invalid input generation.** Deliberately violate constraints to find parsing and validation bugs.

## Relevant work

- **RESTler** (Microsoft Research, Vargas et al.) — stateful REST API fuzzing that builds a dependency graph from the OpenAPI spec and uses dynamic feedback to refine request sequences.
- **EvoMaster** — evolutionary black/white/grey-box test generation for web APIs; uses code instrumentation when available.
- **Morest** (Liu et al.) — model-based REST API testing with state fuzzing.
- **Schemathesis** — practical Python tool that property-tests APIs from OpenAPI specs; good baseline for the current Python stack.

## Takeaway for SentinelAPI

Replace the hard-coded `/register` flow with an automatic producer-consumer resolver. The scanner should:

1. Read the spec.
2. Build a dependency graph of parameters (which response field feeds which path param).
3. Generate minimal sequences that create resources, then exercise every `GET /{resource}/{id}` under multiple auth contexts.
4. Cache created resources so BOLA tests do not depend on a single registration endpoint.

## Prototype path

- Add `DependencyGraph` class in `scanner/`.
- Use `openapi-spec-validator` or `prance` for robust spec parsing.
- For each parameterized path, find a candidate producer endpoint by matching returned property names to path parameter names.
