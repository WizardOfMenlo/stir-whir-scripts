use std::{f64::consts::LOG2_10, fmt::Display, str::FromStr};

/// Security assumptions determines which proximity parameters and conjectures are assumed by the error computation.
#[derive(Debug, Clone, Copy)]
pub enum SecurityAssumption {
    /// Unique decoding assumes that the distance of each oracle is within the UDR of the code.
    /// We refer to this configuration as UD for short.
    /// This requires no conjectures neither in STIR nor WHIR.
    UniqueDecoding,

    /// Johnson bound assumes that the distance of each oracle is within the Johnson bound (1 - sqrt(rho)).
    /// We refer to this configuration as JB for short.
    /// In STIR, this requires no conjecture.
    /// In WHIR, this assumes that RS have mutual correlated agreement for proximity parameter up to (1 - sqrt(rho)).
    JohnsonBound,

    /// Capacity bound assumes that the distance of each oracle is within the capacity bound 1 - rho.
    /// We refer to this configuration as CB for short.
    /// In both STIR and WHIR this requires conjecturing that RS codes are decodable up to capacity and have correlated agreement (mutual in WHIR) up to capacity.
    CapacityBound,
}

impl SecurityAssumption {
    /// In both JB and CB theorems such as list-size only hold for proximity parameters slighly below the bound.
    /// E.g. in JB proximity gaps holds for every delta \in (0, 1 - sqrt(rho)).
    /// Eta is the distance between the chosen proximity parameter and the bound.
    /// I.e. in JB delta = 1 - sqrt(rho) - eta and in CB delta = 1 - rho - eta.
    // TODO: Maybe it makes more sense to be multiplicative. I think this can be set in a better way.
    pub fn log_eta(&self, log_inv_rate: usize) -> f64 {
        // Ask me how I did this? At the time, only God and I knew. Now only God knows
        // I joke, I actually know but this is left for posterity.
        match self {
            // We don't use eta in UD
            Self::UniqueDecoding => 0., // TODO: Maybe just panic and avoid calling it in UD?
            // Set as sqrt(rho)/20
            Self::JohnsonBound => -(0.5 * log_inv_rate as f64 + LOG2_10 + 1.),
            // Set as rho/20
            Self::CapacityBound => -(log_inv_rate as f64 + LOG2_10 + 1.),
        }
    }

    /// Given a RS code (specified by the log of the degree and log inv of the rate), compute the list size at the specified distance delta.
    pub fn list_size_bits(&self, log_degree: usize, log_inv_rate: usize) -> f64 {
        let log_eta = self.log_eta(log_inv_rate);
        match self {
            // In UD the list size is 1
            Self::UniqueDecoding => 0.,

            // By the JB, RS codes are (1 - sqrt(rho) - eta, (2*eta*sqrt(rho))^-1)-list decodable.
            Self::JohnsonBound => {
                let log_inv_sqrt_rate: f64 = log_inv_rate as f64 / 2.;
                log_inv_sqrt_rate - (1. + log_eta)
            }
            // In CB we assume that RS codes are (1 - rho - eta, d/rho*eta)-list decodable (see Conjecture 5.6 in STIR).
            Self::CapacityBound => (log_degree + log_inv_rate) as f64 - log_eta,
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
        // The error computed here is from [BCIKS20] for the combination of two functions. Then we multiply it by the folding factor.
        let log_eta = self.log_eta(log_inv_rate);
        // Note that this does not include the field_size
        let error = match self {
            // In UD the error is |L|/|F| = d/rate*|F|
            Self::UniqueDecoding => (log_degree + log_inv_rate) as f64,

            // In JB the error is degree^2/|F| * (2 * min{ 1 - sqrt(rho) - delta, sqrt(rho)/20 })^7
            // Since delta = 1 - sqrt(rho) - eta then 1 - sqrt(rho) - delta = eta
            // Thus the error is degree^2/|F| * (2 * min { eta, sqrt(rho)/20 })^7
            Self::JohnsonBound => {
                let numerator = (2 * log_degree) as f64;
                let sqrt_rho_20 = 1. + LOG2_10 + 0.5 * log_inv_rate as f64;
                numerator + 7. * (sqrt_rho_20.min(-log_eta) - 1.)
            }

            // In JB we assume the error is degree/eta*rate^2
            Self::CapacityBound => (log_degree + 2 * log_inv_rate) as f64 - log_eta,
        };

        // Error is  (2**folding_factor - 1) * error/|F|;
        let folding_factor_1_log = (((1 << folding_factor) - 1) as f64).log2();
        field_size_bits as f64 - (error + folding_factor_1_log as f64)
    }

    /// Compute a number of queries to match the security level
    pub fn queries(&self, protocol_security_level: usize, log_inv_rate: usize) -> usize {
        // TODO: This is discounting the effect of eta.
        let num_queries_f = match self {
            Self::UniqueDecoding => {
                let rate = 1. / ((1 << log_inv_rate) as f64);
                let denom = (0.5 * (1. + rate)).log2();

                -(protocol_security_level as f64) / denom
            }
            Self::JohnsonBound => (2 * protocol_security_level) as f64 / log_inv_rate as f64,
            Self::CapacityBound => protocol_security_level as f64 / log_inv_rate as f64,
        };

        num_queries_f.ceil() as usize
    }

    pub fn queries_error(&self, log_inv_rate: usize, num_queries: usize) -> f64 {
        let num_queries = num_queries as f64;
        match self {
            Self::UniqueDecoding => {
                let rate = 1. / ((1 << log_inv_rate) as f64);
                let denom = -(0.5 * (1. + rate)).log2();

                num_queries * denom
            }
            Self::JohnsonBound => num_queries * 0.5 * log_inv_rate as f64,
            Self::CapacityBound => num_queries * log_inv_rate as f64,
        }
    }

    pub fn ood_error(
        &self,
        log_degree: usize,
        log_inv_rate: usize,
        field_size_bits: usize,
        ood_samples: usize,
    ) -> f64 {
        let list_size_bits = self.list_size_bits(log_degree, log_inv_rate);

        let error = 2. * list_size_bits + (log_degree * ood_samples) as f64;
        (ood_samples * field_size_bits) as f64 + 1. - error
    }

    pub fn ood_samples(
        &self,
        security_level: usize,
        log_degree: usize,
        log_inv_rate: usize,
        field_size_bits: usize,
    ) -> usize {
        if matches!(self, Self::UniqueDecoding) {
            0
        } else {
            for ood_samples in 1..64 {
                if self.ood_error(log_degree, log_inv_rate, field_size_bits, ood_samples)
                    >= security_level as f64
                {
                    return ood_samples;
                }
            }

            panic!("Could not find an appropriate number of OOD samples");
        }
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

#[cfg(test)]
mod tests {
    use super::SecurityAssumption;

    #[test]
    fn test_ud_errors() {
        let assumption = SecurityAssumption::UniqueDecoding;

        // Setting
        let log_degree = 20;
        let degree = (1 << log_degree) as f64;
        let log_inv_rate = 2;
        let rate = 1. / (1 << log_inv_rate) as f64;

        let field_size_bits = 128;

        // List size
        assert_eq!(assumption.list_size_bits(log_degree, log_inv_rate), 0.);

        // Prox gaps
        let computed_error =
            assumption.prox_gaps_error(log_degree, log_inv_rate, field_size_bits, 1);
        let real_error_non_log = degree / rate;
        let real_error = field_size_bits as f64 - real_error_non_log.log2();

        assert!((computed_error - real_error).abs() < 0.01);
    }

    #[test]
    fn test_jb_errors() {
        let assumption = SecurityAssumption::JohnsonBound;

        // Setting
        let log_degree = 20;
        let degree = (1 << log_degree) as f64;
        let log_inv_rate = 2;
        let rate = 1. / (1 << log_inv_rate) as f64;

        let eta = rate.sqrt() / 20.;
        let delta = 1. - rate.sqrt() - eta;

        let field_size_bits = 128;

        // List size
        let real_list_size = 1. / (2. * eta * rate.sqrt());
        let computed_list_size = assumption.list_size_bits(log_degree, log_inv_rate);
        assert!((real_list_size.log2() - computed_list_size).abs() < 0.01);

        // Prox gaps
        let computed_error =
            assumption.prox_gaps_error(log_degree, log_inv_rate, field_size_bits, 1);
        let real_error_non_log =
            degree.powi(2) / (2. * (rate.sqrt() / 20.).min(1. - rate.sqrt() - delta)).powi(7);
        let real_error = field_size_bits as f64 - real_error_non_log.log2();

        assert!((computed_error - real_error).abs() < 0.01);
    }

    #[test]
    fn test_cb_errors() {
        let assumption = SecurityAssumption::CapacityBound;

        // Setting
        let log_degree = 20;
        let degree = (1 << log_degree) as f64;
        let log_inv_rate = 2;
        let rate = 1. / (1 << log_inv_rate) as f64;

        let eta = rate / 20.;

        let field_size_bits = 128;

        // List size
        let real_list_size = degree / (rate * eta);
        let computed_list_size = assumption.list_size_bits(log_degree, log_inv_rate);
        assert!((dbg!(real_list_size.log2()) - dbg!(computed_list_size)).abs() < 0.01);

        // Prox gaps
        let computed_error =
            assumption.prox_gaps_error(log_degree, log_inv_rate, field_size_bits, 1);
        let real_error_non_log = degree / (eta * rate.powi(2));
        let real_error = field_size_bits as f64 - real_error_non_log.log2();

        assert!((computed_error - real_error).abs() < 0.01);
    }
}
