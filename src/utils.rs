pub(crate) fn pow_util(security_level: usize, error: f64) -> f64 {
    0f64.max(security_level as f64 - error)
}
