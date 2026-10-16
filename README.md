# tracekit

Shared Rust crates for eBPF tracing tools on Linux.

| Crate | What it does |
| --- | --- |
| [`tracekit-wire`](crates/wire) | Declare kernel/user ABI types once in Rust and generate the matching C header. The header has `_Static_assert`s for layout and an ABI hash. Supports zero-copy decoding of ring buffer and map data. `no_std`. |
| [`procctx`](crates/procctx) | Process context from fork/exec/exit events with `/proc` fallback: ancestry (including exited parents), cgroup, systemd unit, container and tmux pane, and which build step started a process (npm/pnpm/yarn/bun lifecycle scripts, Cargo build scripts, pip builds, `make`). |
| [`bpfdoctor`](crates/bpfdoctor) | Preflight checks for BPF tools: capabilities, kernel version and BTF, lockdown, sysctls, memlock, containers, user namespaces and seccomp. Each problem it reports comes with the exact command that fixes it. Output as human-readable text or JSON. |

Each crate's rustdoc has a worked example.

## Usage

The crates are not on crates.io. Depend on them through git, pinned to a release tag:

```toml
[dependencies]
tracekit-wire = { git = "https://github.com/Arinerron/tracekit", tag = "v0.1.0" }
procctx = { git = "https://github.com/Arinerron/tracekit", tag = "v0.1.0" }
bpfdoctor = { git = "https://github.com/Arinerron/tracekit", tag = "v0.1.0" }

[build-dependencies]
tracekit-wire = { git = "https://github.com/Arinerron/tracekit", tag = "v0.1.0", features = ["std"] }
```

## Requirements

- Linux (`procctx` and `bpfdoctor` read `/proc` and `/sys`).
- Rust 1.94 or newer.

## Features

- `tracekit-wire/std`: `HeaderBuilder` for generating C headers. Turn it on in `[build-dependencies]`.
- `procctx/testing`: `testing::FixtureSource`, a `ProcSource` over a fixture tree that can inject faults.
- `bpfdoctor/testing`: `FixtureEnv`, for testing a tool's own checks against fixture trees.

## License

MIT. See [LICENSE](LICENSE).
