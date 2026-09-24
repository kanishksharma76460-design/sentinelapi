# Response-Schema Oracles

## Core idea

When a response contains fields not declared in the OpenAPI schema, that is a contract violation. If those fields are sensitive, it is a data-exposure vulnerability.

## Dimensions

- **Flat key diff.** Top-level keys only (current implementation).
- **Recursive schema diff.** Nested objects and arrays; current code does not recurse.
- **Type mismatch.** A field is declared as `string` but returned as an object containing a hash.
- **Sensitivity classification.** Keyword lists are brittle; better oracles use regex, NER, or LLM classification.

## Relevant work

- **OpenAPI response validation** libraries — `openapi-core`, `fastapi` itself, `jsonschema`.
- **PII detection** — Presidio (Microsoft), Google Cloud DLP, regex-based classifiers.
- **Schema inference** — infer expected schema from many responses and diff against spec.

## Takeaway for SentinelAPI

Upgrade the exposure check:

1. Recursively validate response bodies against declared schemas.
2. Classify undeclared fields as sensitive using both keyword matching and pattern rules.
3. Add a *missing-field* oracle too: if a field is declared but absent, it is a lower-severity finding (contract drift).
4. Flag nested leaks, e.g. `{ "user": { "ssn": "..." } }`.

## Prototype path

- Replace `schema_keys()` with a recursive schema walker.
- Add `sensitive_classify()` with keyword + regex + optional Presidio integration.
- Add a recursive `find_undeclared()` function that returns paths, not just keys.
