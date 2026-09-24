# REST API Fuzzing

## Core idea

Fuzzing REST APIs is hard because inputs are structured (JSON, query params, headers) and many random mutations produce immediate 400s. The state of the art uses grammar awareness and dynamic feedback.

## Key techniques

- **Grammar-aware fuzzing.** Respect OpenAPI types/formats but push boundaries: huge integers, unicode, arrays, nested objects.
- **Dictionary fuzzing.** Maintain dictionaries of interesting values: `"../etc/passwd"`, SQLi payloads, SSRF URLs, JSON injection strings.
- **Coverage-guided fuzzing.** Use runtime instrumentation to prefer inputs that reach new code paths. Hard for black-box targets but EvoMaster demonstrates it.
- **Stateful fuzzing.** Mutate sequences of calls, not single requests; maintain server-side state across the sequence.

## Relevant work

- **RESTler** — grammar-based stateful fuzzing with dynamic feedback.
- **EvoMaster** — evolutionary black/white/grey-box REST fuzzing.
- **Morest** — model-based REST testing.
- **crAPI** — completely ridiculous API, a deliberately vulnerable training API with realistic business logic.
- **APIFuzzer**, **Restler-fuzzer**, **TNT-Fuzzer** — earlier grammar-aware tools.

## Takeaway for SentinelAPI

SentinelAPI is currently not a fuzzer; it is a targeted differential tester. Adding fuzzing would broaden findings:

1. **Input-boundary fuzzing.** For each parameter, generate edge values and compare schema violations to security failures.
2. **Mass assignment.** Send extra body fields (`is_admin`, `role`, `balance`) and check if the server stores them.
3. **IDOR via type confusion.** Use string versions of IDs (`"1"` instead of `1`) or arrays (`[1,2]`).

## Prototype path

- Add a `Fuzzer` module with per-parameter mutation strategies.
- Add a `MassAssignment` check: append suspicious fields to request bodies and observe responses.
- Log status-code / response-size differences across mutations as low-confidence findings.
