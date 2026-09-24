# LLM-Assisted Security Testing

## Core idea

Large language models can read OpenAPI specs and natural-language descriptions and infer likely auth rules, sensitive fields, and edge cases that a pure grammar-based scanner would miss.

## Use cases

| Task | LLM prompt shape | Value |
|---|---|---|
| Infer auth intent | "Given this spec, which endpoints should require authentication?" | Catch missing auth |
| Generate edge cases | "List unusual but valid values for parameter X" | Fuzzing seeds |
| Semantic leak detection | "Should a user with role R see field F?" | Better exposure oracle |
| Exploit narration | "Explain why this response indicates a BOLA bug" | Report writing |

## Caveats

- LLMs are **slow and non-deterministic**; use them as an oracle or pre-processor, not on every request.
- They can hallucinate auth rules. Always ground in observed behavior.
- Prefer smaller, cheaper models for classification tasks; reserve large models for report generation.

## Relevant work

- **Fuzz4All** / **TitanFuzz** — LLM-based fuzzing (general, not API-specific).
- **LLM4Vuln** and related workshops — using LLMs to interpret security-relevant behavior.
- Industry prototypes using GPT-4 to review API diffs and flag sensitive-data exposure.

## Takeaway for SentinelAPI

Add an optional LLM module that runs *after* the deterministic scanner:

1. Feed the spec + a suspicious response to the model.
2. Ask: "Is field X appropriate for user with role Y on endpoint Z?"
3. Use the answer to upgrade a MEDIUM exposure finding to HIGH or CRITICAL.
4. Generate plain-language explanations for the HTML report.

## Prototype path

- Add `scanner/llm_oracle.py` with a small wrapper around OpenAI/Anthropic/local LLM.
- Define a strict JSON schema for the model response to avoid parsing noise.
- Cache results to avoid repeated calls.
