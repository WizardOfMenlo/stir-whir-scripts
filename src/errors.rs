use std::{f64::consts::LOG2_10, fmt::Display, str::FromStr};

#[derive(Debug, Clone, Copy)]
pub enum SecurityAssumption {
    UniqueDecoding,
    JohnsonBound,
    CapacityBound,
}

impl SecurityAssumption {
    /// Given a rate, computes a suitable eta to use
    pub fn log_eta(&self, log_inv_rate: usize) -> f64 {
        // Ask me how I did this? At the time, only God and I knew. Now only God knows
        match self {
            Self::UniqueDecoding => 0.,
            Self::JohnsonBound => -(0.5 * log_inv_rate as f64 + LOG2_10 + 1.),
            Self::CapacityBound => -(log_inv_rate as f64 + 1.),
        }
    }

    /// Given a RS code (specified by the log of the degree and log inv of the rate), compute the list size at the specified distance.
    pub fn list_size_bits(&self, log_degree: usize, log_inv_rate: usize) -> f64 {
        let log_eta = self.log_eta(log_inv_rate);
        match self {
            Self::UniqueDecoding => 0.,
            Self::CapacityBound => (log_degree + log_inv_rate) as f64 - log_eta,
            Self::JohnsonBound => {
                let log_inv_sqrt_rate: f64 = log_inv_rate as f64 / 2.;
                log_inv_sqrt_rate - (1. + log_eta)
            }
        }
    }

    /// Given a RS code (specified by the log of the degree and log inv of the rate) a field_size and an arity, compute the proximity gaps error (in bits) at the specified distance
    pub fn prox_gaps_error(
        &self,
        log_degree: usize,
        log_inv_rate: usize,
        field_size_bits: usize,
        folding_factor: usize,
    ) -> f64 {
        let log_eta = self.log_eta(log_inv_rate);
        let error = match self {
            Self::CapacityBound => (log_degree + log_inv_rate) as f64 - log_eta,
            Self::JohnsonBound => LOG2_10 + 3.5 * log_inv_rate as f64 + 2. * log_degree as f64,
            Self::UniqueDecoding => (log_degree + log_inv_rate) as f64,
        };

        // TODO: The folding_factor is not exactly correct
        field_size_bits as f64 - (error + folding_factor as f64)
    }
}

impl Display for SecurityAssumption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match &self {
                SecurityAssumption::UniqueDecoding => "UniqueDecoding",
                SecurityAssumption::JohnsonBound => "JohnsonBound",
                SecurityAssumption::CapacityBound => "CapacityBound",
            }
        )
    }
}

impl FromStr for SecurityAssumption {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "UniqueDecoding" {
            Ok(SecurityAssumption::UniqueDecoding)
        } else if s == "JohnsonBound" {
            Ok(SecurityAssumption::JohnsonBound)
        } else if s == "CapacityBound" {
            Ok(SecurityAssumption::CapacityBound)
        } else {
            Err(format!("Invalid soundness specification: {}", s))
        }
    }
}
