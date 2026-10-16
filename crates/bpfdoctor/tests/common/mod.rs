use bpfdoctor::{Cap, FixtureEnv, Tool};

pub fn tool() -> Tool {
    Tool {
        name: "whytime",
        exe: "/usr/local/bin/whytime".into(),
        required_caps: &[Cap::Bpf, Cap::Perfmon],
        optional_caps: &[(Cap::SysPtrace, "names of other users' processes")],
        min_kernel: (5, 8),
        memlock_bytes: 64 << 20,
    }
}

/// A healthy host running as root, backed by `tests/fixtures/host`.
pub fn host() -> FixtureEnv {
    FixtureEnv::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/host"))
}
