use super::ProxGapsType;
use std::fmt::Display;

#[derive(Clone)]
pub struct WhirParameters {
    pub starting_log_inv_rate: usize,
    pub folding_factor: usize, // TODO: Change to vary number of bits
    pub soundness_type: ProxGapsType,
    pub security_level: usize,
    pub pow_bits: usize,
}

impl Display for WhirParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Targeting {}-bits of security with {}-bits of PoW - soundness: {:?}",
            self.security_level, self.pow_bits, self.soundness_type
        )?;
        writeln!(
            f,
            "Starting rate: 2^-{}, folding_factor: {}",
            self.starting_log_inv_rate, self.folding_factor,
        )
    }
}
