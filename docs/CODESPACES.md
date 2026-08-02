# GitHub Codespaces

Use Codespaces when local builds would compete with browsers, video, or other desktop work. It is the recommended remote Linux development environment for Lens source checks, headless proxy validation, documentation checks, and release-gate rehearsal.

Codespaces does not replace Windows, macOS, or clean-machine dogfood validation. Use GitHub Actions for cross-platform CI and release artifacts, and use a real Windows machine for WFP driver validation.

## Start a Codespace

1. Open the repository on GitHub.
2. Select **Code** > **Codespaces** > **Create codespace on main**.
3. Wait for the devcontainer setup to finish.

The container installs Rust, rustfmt, clippy, Python, Clang/LLVM, libelf, OpenSSL headers, and Linux headers. The post-create step checks the locked Cargo graph but does not run a full build.

## Run the normal checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
python -m unittest discover -s scripts -p "test_*.py"
python scripts/release_gate.py
python scripts/check-markdown-links.py
```

For a Linux release-style build with optional eBPF discovery:

```sh
cargo build --locked --release -p lens-cli --features ebpf
```

## Run Lens remotely

Codespaces forwards these common Lens ports:

| Port | Use |
| --- | --- |
| 8888 | HTTP/HTTPS explicit proxy |
| 15432 | PostgreSQL fixed-target endpoint |
| 16379 | Redis fixed-target endpoint |
| 18080 | HTTP/2 fixed-target endpoint |
| 15051 | gRPC fixed-target endpoint |

For headless HTTP validation inside the Codespace:

```sh
cargo run -p lens-cli -- run --headless --listen 127.0.0.1:8888 --export target/codespaces-http.jsonl
```

In another Codespaces terminal:

```sh
HTTP_PROXY=http://127.0.0.1:8888 curl http://example.com/
```

Prefer `--headless` for remote checks. Interactive TUI testing works in the terminal, but final TUI acceptance should still be done on a normal local terminal before release.

## Boundaries

- Codespaces is Linux only for this repository configuration.
- Transparent Windows interception and driver signing are not validated in Codespaces.
- macOS signing, notarization, and Windows Authenticode signing remain GitHub Actions release jobs.
- Use GitHub Actions for authoritative cross-platform results before merging release-impacting changes.
