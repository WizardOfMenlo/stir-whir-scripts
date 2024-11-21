use crate::{errors::SecurityAssumption, LowDegreeParameters};

#[derive(Clone)]
pub struct StirParameters {
    pub starting_log_inv_rate: usize,
    pub folding_factor: usize, // TODO: Change to vary number of bits
    pub list_assumption: SecurityAssumption,
    pub security_level: usize,
    pub pow_bits: usize,
}

#[derive(Clone)]
pub struct StirConfig {
    pub(crate) mv_parameters: LowDegreeParameters,
    pub(crate) security_assumption: SecurityAssumption,
    pub(crate) security_level: usize,
    pub(crate) max_pow_bits: usize,

    //pub(crate) starting_domain: Domain<F>,
    pub(crate) starting_log_inv_rate: usize,
    pub(crate) starting_folding_pow_bits: f64,

    pub(crate) round_parameters: Vec<RoundConfig>,

    pub(crate) final_queries: usize,
    pub(crate) final_pow_bits: f64,
    pub(crate) final_log_inv_rate: usize,
    pub(crate) final_folding_pow_bits: f64,
}

#[derive(Debug, Clone)]
pub(crate) struct RoundConfig {
    pub(crate) folding_factor: usize,
    pub(crate) pow_bits: f64,
    pub(crate) folding_pow_bits: f64,
    pub(crate) num_queries: usize,
    pub(crate) ood_samples: usize,
    pub(crate) log_inv_rate: usize,
}

impl StirConfig {
    pub fn new(ldt_parameters: LowDegreeParameters, stir_parameters: StirParameters) -> Self {
        // We need to fold at least some time
        assert!(
            stir_parameters.folding_factor > 0,
            "folding factor should be non zero"
        );
        // If less, just send the damn polynomials
        assert!(ldt_parameters.num_variables >= stir_parameters.folding_factor);

        let protocol_security_level =
            0.max(stir_parameters.security_level - stir_parameters.pow_bits);

        let starting_domain = Domain::new(
            1 << ldt_parameters.num_variables,
            stir_parameters.starting_log_inv_rate,
        )
        .expect("Should have found an appropriate domain - check Field 2 adicity?");

        let final_sumcheck_rounds = ldt_parameters.num_variables % stir_parameters.folding_factor;
        let num_rounds = ((ldt_parameters.num_variables - final_sumcheck_rounds)
            / stir_parameters.folding_factor)
            - 1;

        let field_size_bits = F::field_size_in_bits();

        let committment_ood_samples = Self::ood_samples(
            stir_parameters.security_level,
            stir_parameters.soundness_type,
            ldt_parameters.num_variables,
            stir_parameters.starting_log_inv_rate,
            Self::log_eta(
                stir_parameters.soundness_type,
                stir_parameters.starting_log_inv_rate,
            ),
            field_size_bits,
        );

        let starting_folding_pow_bits = Self::folding_pow_bits(
            stir_parameters.security_level,
            stir_parameters.soundness_type,
            field_size_bits,
            ldt_parameters.num_variables,
            stir_parameters.starting_log_inv_rate,
            Self::log_eta(
                stir_parameters.soundness_type,
                stir_parameters.starting_log_inv_rate,
            ),
        );

        let mut round_parameters = Vec::with_capacity(num_rounds);
        let mut num_variables = ldt_parameters.num_variables - stir_parameters.folding_factor;
        let mut log_inv_rate = stir_parameters.starting_log_inv_rate;
        for _ in 0..num_rounds {
            // Queries are set w.r.t. to old rate, while the rest to the new rate
            let next_rate = log_inv_rate + (stir_parameters.folding_factor - 1);

            let log_next_eta = Self::log_eta(stir_parameters.soundness_type, next_rate);
            let num_queries = Self::queries(
                stir_parameters.soundness_type,
                protocol_security_level,
                log_inv_rate,
            );

            let ood_samples = Self::ood_samples(
                stir_parameters.security_level,
                stir_parameters.soundness_type,
                num_variables,
                next_rate,
                log_next_eta,
                field_size_bits,
            );

            let query_error =
                Self::rbr_queries(stir_parameters.soundness_type, log_inv_rate, num_queries);
            let combination_error = Self::rbr_soundness_queries_combination(
                stir_parameters.soundness_type,
                field_size_bits,
                num_variables,
                next_rate,
                log_next_eta,
                ood_samples,
                num_queries,
            );

            let pow_bits = 0_f64
                .max(stir_parameters.security_level as f64 - (query_error.min(combination_error)));

            let folding_pow_bits = Self::folding_pow_bits(
                stir_parameters.security_level,
                stir_parameters.soundness_type,
                field_size_bits,
                num_variables,
                next_rate,
                log_next_eta,
            );

            round_parameters.push(RoundConfig {
                ood_samples,
                num_queries,
                pow_bits,
                folding_pow_bits,
                log_inv_rate,
            });

            num_variables -= stir_parameters.folding_factor;
            log_inv_rate = next_rate;
        }

        let final_queries = Self::queries(
            stir_parameters.soundness_type,
            protocol_security_level,
            log_inv_rate,
        );

        let final_pow_bits = 0_f64.max(
            stir_parameters.security_level as f64
                - Self::rbr_queries(stir_parameters.soundness_type, log_inv_rate, final_queries),
        );

        let final_folding_pow_bits =
            0_f64.max(stir_parameters.security_level as f64 - (field_size_bits - 1) as f64);

        StirConfig {
            security_level: stir_parameters.security_level,
            max_pow_bits: stir_parameters.pow_bits,
            mv_parameters: ldt_parameters,
            security_assumption: stir_parameters.security_assumption,
            starting_log_inv_rate: stir_parameters.starting_log_inv_rate,
            starting_folding_pow_bits,
            round_parameters,
            final_queries,
            final_pow_bits,
            final_folding_pow_bits,
            final_log_inv_rate: log_inv_rate,
        }
    }
}
