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
