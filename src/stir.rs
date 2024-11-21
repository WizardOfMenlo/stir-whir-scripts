use crate::{errors::SecurityAssumption, LowDegreeParameters};

#[derive(Clone)]
pub struct StirParameters {
    // Relate to the first round
    pub starting_log_inv_rate: usize,
    pub starting_folding_factor: usize,

    // The following relate only to the internal rounds
    pub folding_factors: Vec<usize>,
    pub evaluation_domain_log_sizes: Vec<usize>,

    pub security_assumption: SecurityAssumption,
    pub security_level: usize,
    pub pow_bits: usize,
}

#[derive(Clone)]
pub struct StirConfig {
    pub(crate) ldt_parameters: LowDegreeParameters,
    pub(crate) security_assumption: SecurityAssumption,
    pub(crate) security_level: usize,
    pub(crate) max_pow_bits: usize,

    pub(crate) starting_folding_factor: usize,
    pub(crate) starting_domain_log_size: usize,
    pub(crate) starting_log_inv_rate: usize,
    pub(crate) starting_folding_pow_bits: f64,

    pub(crate) round_parameters: Vec<RoundConfig>,

    pub(crate) final_log_degree: usize,
    pub(crate) final_queries: usize,
    pub(crate) final_pow_bits: f64,
    pub(crate) final_log_inv_rate: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct RoundConfig {
    pub(crate) folding_factor: usize,
    pub(crate) evaluation_domain_log_size: usize,
    pub(crate) pow_bits: f64,
    pub(crate) num_queries: usize,
    pub(crate) ood_samples: usize,
    pub(crate) log_inv_rate: usize,
}

fn pow_util(security_level: usize, error: f64) -> f64 {
    0f64.max(security_level as f64 - error)
}

impl StirConfig {
    pub fn new(ldt_parameters: LowDegreeParameters, stir_parameters: StirParameters) -> Self {
        // We need to fold at least some time
        assert!(
            stir_parameters.starting_folding_factor > 0
                && stir_parameters.folding_factors.iter().all(|&x| x > 0),
            "folding factors should be non zero"
        );
        assert_eq!(
            stir_parameters.folding_factors.len(),
            stir_parameters.evaluation_domain_log_sizes.len()
        );

        // We cannot fold too much
        let total_reduction = stir_parameters.starting_folding_factor
            + stir_parameters.folding_factors.iter().sum::<usize>();
        assert!(total_reduction <= ldt_parameters.log_degree);

        // If less, just send the damn polynomials
        assert!(ldt_parameters.log_degree >= stir_parameters.folding_factors[0]);

        // Compute the number of rounds and the leftover
        let final_log_degree = ldt_parameters.log_degree - total_reduction;
        let num_rounds = stir_parameters.folding_factors.len();

        // Compute the security level
        let security_level = stir_parameters.security_level;
        let protocol_security_level =
            0.max(stir_parameters.security_level - stir_parameters.pow_bits);

        // Initial domain size (the trace domain)
        let starting_folding_factor = stir_parameters.folding_factors[0];
        let starting_domain_log_size =
            ldt_parameters.log_degree + stir_parameters.starting_log_inv_rate;

        let mut current_log_degree = ldt_parameters.log_degree - starting_folding_factor;
        let mut log_inv_rate = stir_parameters.starting_log_inv_rate;

        // We now start, the initial folding pow bits
        let starting_folding_pow_bits = pow_util(
            security_level,
            stir_parameters.security_assumption.prox_gaps_error(
                current_log_degree,
                log_inv_rate,
                ldt_parameters.field.extension_bit_size(),
                stir_parameters.folding_factors[0],
            ),
        );

        let mut round_parameters = Vec::with_capacity(num_rounds);

        for (folding_factor, new_evaluation_domain_size) in stir_parameters
            .folding_factors
            .into_iter()
            .zip(stir_parameters.evaluation_domain_log_sizes)
        {
            // Queries are set w.r.t. to the old rate, while the reset to the new rate
            let next_rate = new_evaluation_domain_size - (current_log_degree - folding_factor);

            // Compute the ood samples required
            let ood_samples = stir_parameters.security_assumption.ood_samples(
                security_level,
                current_log_degree,
                next_rate,
                ldt_parameters.field.extension_bit_size(),
            );

            // Compute the number of queries required
            let num_queries = stir_parameters
                .security_assumption
                .queries(protocol_security_level, log_inv_rate);

            // We need to compute the errors, to compute the according PoW
            let query_error = stir_parameters
                .security_assumption
                .queries_error(log_inv_rate, num_queries);

            let prox_gaps_error_1 = stir_parameters.security_assumption.prox_gaps_error(
                current_log_degree,
                next_rate,
                ldt_parameters.field.extension_bit_size(),
                ((num_queries + ood_samples) as f64).log2().ceil() as usize, // We want this in log
                                                                             // form
            );

            let prox_gaps_error_2 = stir_parameters.security_assumption.prox_gaps_error(
                current_log_degree - folding_factor,
                next_rate,
                ldt_parameters.field.extension_bit_size(),
                folding_factor,
            );

            // Now compute the PoW
            let pow_bits = pow_util(
                security_level,
                query_error.max(prox_gaps_error_1).max(prox_gaps_error_2),
            );

            let round_config = RoundConfig {
                evaluation_domain_log_size: new_evaluation_domain_size,
                folding_factor,
                num_queries,
                pow_bits,
                ood_samples,
                log_inv_rate,
            };
            round_parameters.push(round_config);

            log_inv_rate = next_rate;
            current_log_degree -= folding_factor;
        }

        // Compute the number of queries required
        let final_queries = stir_parameters
            .security_assumption
            .queries(protocol_security_level, log_inv_rate);

        // We need to compute the errors, to compute the according PoW
        let query_error = stir_parameters
            .security_assumption
            .queries_error(log_inv_rate, final_queries);

        // Now compute the PoW
        let final_pow_bits = pow_util(security_level, query_error);

        StirConfig {
            ldt_parameters,
            security_assumption: stir_parameters.security_assumption,
            security_level,
            max_pow_bits: stir_parameters.pow_bits,
            starting_folding_factor,
            starting_domain_log_size,
            starting_log_inv_rate: stir_parameters.starting_log_inv_rate,
            starting_folding_pow_bits,
            round_parameters,
            final_queries,
            final_pow_bits,
            final_log_degree,
            final_log_inv_rate: log_inv_rate,
        }
    }
}
