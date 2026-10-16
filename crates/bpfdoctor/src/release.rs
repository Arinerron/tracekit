//! Kernel release parsing.

/// Parses the numeric prefix of a kernel release into `(major, minor, patch)`.
///
/// Distro suffixes are ignored and a missing patch level reads as 0:
/// `"5.15.0-91-generic"` → `(5, 15, 0)`, `"6.10-rc3"` → `(6, 10, 0)`.
pub fn parse_release(s: &str) -> Option<(u32, u32, u32)> {
    let (major, rest) = leading_number(s.trim())?;
    let (minor, rest) = leading_number(rest.strip_prefix('.')?)?;
    let patch = rest
        .strip_prefix('.')
        .and_then(leading_number)
        .map_or(0, |(patch, _)| patch);
    Some((major, minor, patch))
}

/// Splits a non-empty run of leading ASCII digits off `s`.
fn leading_number(s: &str) -> Option<(u32, &str)> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    Some((s[..end].parse().ok()?, &s[end..]))
}

#[cfg(test)]
mod tests {
    use super::parse_release;

    #[test]
    fn parses_distro_releases() {
        assert_eq!(parse_release("7.2.6-arch2-1"), Some((7, 2, 6)));
        assert_eq!(parse_release("5.15.0-91-generic"), Some((5, 15, 0)));
        assert_eq!(parse_release("4.18.0-513.el8.x86_64"), Some((4, 18, 0)));
        assert_eq!(parse_release("6.1.0-27-amd64\n"), Some((6, 1, 0)));
        assert_eq!(parse_release("5.10.226+"), Some((5, 10, 226)));
    }

    #[test]
    fn missing_or_non_numeric_patch_reads_as_zero() {
        assert_eq!(parse_release("6.10-rc3"), Some((6, 10, 0)));
        assert_eq!(parse_release("6.8"), Some((6, 8, 0)));
        assert_eq!(parse_release("6.8.rc1"), Some((6, 8, 0)));
    }

    #[test]
    fn rejects_malformed_releases() {
        for bad in ["", "6", "6.", "linux-6.8", ".6.8", "6-8", "99999999999.1.0"] {
            assert_eq!(parse_release(bad), None, "{bad:?}");
        }
    }
}
