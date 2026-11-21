# 0003. Rust for the core, Svelte for the UI, decrypt in the client

- Status: Accepted
- Date: 2026-11-21

## Context

NilPerit has security- and performance-critical parts (crypto, storage, connectors) and parts for average users (configuration, browsing). We want memory safety and native performance where it matters, without making the UI needlessly hard to build. A node may run on a server that only holds a write-only credential (see 0004), so browsing needs the read key somewhere.

## Decision

- **Rust** for the core, connectors, node daemon, CLI and the API. The API runs inside the node (for example `axum`), not as a separate service. The OpenAPI spec is generated from the Rust types (`utoipa`); TypeScript client types are generated from it.
- **Decryption happens in the client.** The read key never leaves the user's device; the server serves encrypted objects. The reader and crypto crates are compiled to WebAssembly for this, so the browser runs the same reviewed code.
- **Svelte + TypeScript** for presentation only. It never handles keys or storage logic. It is built statically and embedded in the node binary; there is no Node.js at runtime.
- Later, a desktop app via **Tauri**, reusing the same frontend.

## Consequences

- All security-critical code is in one language and one code base.
- One binary to deploy on a server, in Kubernetes or on a PC.
- The frontend bundle runs next to decrypted data in the browser, so a compromised npm dependency is not harmless. Mitigations: minimal dependencies, lockfile, `npm ci --ignore-scripts`, reproducible builds, and a strict Content Security Policy (`connect-src 'self'`, no inline scripts) so injected code cannot exfiltrate data.

## Alternatives considered

- **Rust → WASM UI framework (Leptos, Dioxus):** one language, but a small ecosystem and slower iteration on a polished UI for average users.
- **Server-rendered HTML + htmx:** tiny attack surface, but limited for a pleasant archive browser, and it would need decryption on the server.
- **Decrypt on the server:** breaks the write-only node promise.
