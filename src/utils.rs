use std::fmt;

pub(crate) fn pow_util(security_level: usize, error: f64) -> f64 {
    0f64.max(security_level as f64 - error)
}

/// Converts a number of bits into an appropriate unit.
pub(crate) fn display_size(bits: usize) -> String {
    if bits == 0 {
        return "0B".to_owned();
    }

    let size_bytes = bits as f64 / 8.;
    let size_name = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    let i = size_bytes.log(1024_f64).floor() as usize;
    let p = 1024_f64.powf(i as f64);
    let s = (size_bytes / p).round();

    format!("{} {}", s, size_name[i])
}

/// Prints prettily a slice of floats
pub(crate) fn pretty_print_float_slice(f: &mut fmt::Formatter<'_>, v: &[f64]) -> fmt::Result {
    write!(f, "[")?;
    for (i, value) in v.iter().enumerate() {
        if i > 0 {
            write!(f, ", ")?;
        }
        write!(f, "{:.1}", value)?;
    }
    writeln!(f, "]")
}

#[cfg(test)]
mod tests {
    use super::display_size;

    #[test]
    fn test_display_size_zero() {
        assert_eq!(display_size(0), "0B");
    }

    #[test]
    fn test_display_size_one_kb() {
        assert_eq!(display_size(8 * 1024), "1 KB");
    }
}
