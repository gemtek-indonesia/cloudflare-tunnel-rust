# cloudflare-tunnel-rust

Rust implementation targeting wire and CLI compatibility with Cloudflare `cloudflared` **2026.10.0**, pinned to [`18cdfe0a6fc7b72a0702d255a1f984e776ce0498`](https://github.com/cloudflare/cloudflared/tree/18cdfe0a6fc7b72a0702d255a1f984e776ce0498).

**Work in progress; not yet a production drop-in replacement.** Offline protocol and component tests pass. Live Cloudflare edge acceptance has not been completed. See the [compatibility matrix](docs/compatibility.md).

Targets: Linux x86_64, static musl, **x86-64-v2** and **x86-64-v3**. Choose the variant supported by your CPU.

```sh
cargo test --locked --offline
cargo run --locked --offline -- version
```

See [builds and testing](docs/testing.md).

Independent project; not an official Cloudflare distribution. [LICENSE](LICENSE) · [NOTICE](NOTICE)
