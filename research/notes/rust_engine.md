# Rust Engine for SentinelAPI

## Why Rust for this piece

The current scanner is Python `httpx` + `asyncio`. That is fine for the demo, but a Rust engine gives three concrete advantages:

1. **Throughput.** `tokio` + `reqwest` can sustain tens of thousands of concurrent requests with low memory footprint. That matters when you want to fuzz every endpoint under many auth contexts.
2. **Determinism and safety.** No GIL contention, no accidental shared mutable state; the borrow checker enforces clean separation of spec / state / HTTP client.
3. **Deep-tech story.** A Rust core with a Python orchestrator is a strong hackathon narrative: "we wrote the performance-critical scanner in Rust and wrapped it with Python for ease of use."

## Recommended architecture: Rust engine + Python wrapper

```
kanishhacka/
├── engine/                  # Rust crate
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs          # CLI: reads openapi.json + auth contexts, emits findings.json
│       ├── spec.rs          # OpenAPI 3.x parsing
│       ├── scanner.rs       # BOLA + exposure checks
│       ├── oracle.rs        # differential / schema oracles
│       └── report.rs        # HTML + JSON output
├── vuln_api/main.py         # unchanged vulnerable FastAPI target
├── scanner/scanner.py       # keep as Python reference / fallback
├── scanner/orchestrator.py  # FastAPI/subprocess wrapper around the Rust binary
└── run.sh                   # start API → run Rust engine → open report
```

## Crate split options

| Option | Pros | Cons |
|---|---|---|
| Pure Rust CLI (`cargo run`) | Simple, fast, one binary | Must reimplement reporting, harder to iterate |
| Rust engine + Python wrapper (recommended) | Python handles orchestration/reporting; Rust handles HTTP load | Two languages, IPC via JSON |
| Rust lib + PyO3 bindings | Python can call Rust functions directly | More build complexity; may be overkill |

For a hackathon demo, **Rust CLI + Python wrapper** is the sweet spot.

## Key dependencies

| Concern | Crate |
|---|---|
| Async runtime | `tokio` |
| HTTP client | `reqwest` |
| OpenAPI parsing | `openapiv3` |
| CLI / args | `clap` |
| JSON | `serde` + `serde_json` |
| Regex | `regex` |
| Errors | `anyhow` |

## Design sketch

```rust
// engine/src/main.rs
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let spec = fetch_spec(&client, &args.base).await?;
    let principals = register_principals(&client, &args.base, &["alice", "bob"]).await?;

    let endpoints = parameterized_endpoints(&spec);
    let findings = scan(&client, &args.base, &spec, &endpoints, &principals).await;

    write_json(&args.out_json, &findings)?;
    write_html(&args.out_html, &spec, &findings, &args.base)?;
    Ok(())
}
```

## Differences from Python version

1. **Spec parsing.** `openapiv3` gives a typed AST; no more `dict.get()` chains.
2. **Concurrency.** Spawn a bounded `tokio` task per endpoint/context combo; collect results with a channel or `FuturesUnordered`.
3. **Oracles.** Separate module with pure functions: `fn is_bola_leak(response: &Value, principal_b: &Principal) -> bool`.
4. **Output.** Rust emits JSON; Python wrapper can optionally enrich it or regenerate HTML if you prefer to keep the Python report renderer.

## Migration path

1. Create `engine/` crate and reproduce the existing findings against `vuln_api`.
2. Keep `scanner/scanner.py` as a reference until parity is proven.
3. Update `run.sh` to build and call the Rust binary.
4. Extend the Rust engine with stateful sequences / fuzzing.

## Suggested first file set

- `engine/Cargo.toml`
- `engine/src/main.rs`
- `engine/src/spec.rs`
- `engine/src/scanner.rs`
- `engine/src/oracle.rs`
- `engine/src/report.rs`

## Notes

- The Rust engine can read the same `openapi.json` produced by FastAPI, so no spec changes are needed.
- For the hackathon, emphasise that the Rust engine is a drop-in replacement: same inputs, same outputs, but faster and safer.
