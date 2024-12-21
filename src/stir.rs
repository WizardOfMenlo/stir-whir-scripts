use std::fmt::Display;

use crate::{
    errors::SecurityAssumption,
    proof_size::{FieldElements, MerkleQueries, MerkleTree, Proof, ProofElement, ProofRound},
    LowDegreeParameters,
};

/// Parameters parametrizing an instance of STIR.
/// This does not include the entire configuration of STIR, as we populate that later on according to required security config.#[derive(Clone)]
pub struct StirParameters {
    /// The starting rate used in the protocol.
    pub starting_log_inv_rate: usize,

    /// The folding factor in the first round.
    /// Given in log form, i.e. starting_folding_factor = 2 implies that the degree is reduced by a factor of 4.
    pub starting_folding_factor: usize,

    /// The folding factors in the remaining rounds.
    /// Given in log form, i.e. folding_factors[i] = 2 implies that the degree in round i is reduced by a factor of 4.
    pub folding_factors: Vec<usize>,

    /// The rates used in the internal rounds of STIR.
    pub log_inv_rates: Vec<usize>,

    /// The security assumption under which to configure FRI.
    pub security_assumption: SecurityAssumption,

    /// The security level desired.
    pub security_level: usize,

    /// The number of pow bits to use to reduce query error.
    /// Traditionally called also "grinding".
    /// NOTE: This does not affect the pow bits used to reduce proximity gaps errors.
    pub pow_bits: usize,
}

impl StirParameters {
    /// Instantiates a STIR configuration in which the rate is constant. This is a worse version of FRI.
    pub fn fixed_rate_folding(
        log_inv_rate: usize,
        folding_factor: usize,
        num_rounds: usize,
        security_assumption: SecurityAssumption,
        security_level: usize,
        pow_bits: usize,
    ) -> Self {
        StirParameters {
            starting_log_inv_rate: log_inv_rate,
            starting_folding_factor: folding_factor,
            folding_factors: vec![folding_factor; num_rounds],
            log_inv_rates: vec![log_inv_rate; num_rounds],
            security_assumption,
            security_level,
            pow_bits,
        }
    }

    /// A STIR configuration in which the domain shrinks by (1/2) in each iteration while the degree shrinks by (1/2^folding_factor).
    /// This is the version presented in the STIR paper.
    pub fn fixed_domain_shift(
        log_inv_rate: usize,
        folding_factor: usize,
        num_rounds: usize,
        security_assumption: SecurityAssumption,
        security_level: usize,
        pow_bits: usize,
    ) -> Self {
        StirParameters {
            starting_log_inv_rate: log_inv_rate,
            starting_folding_factor: folding_factor,
            folding_factors: vec![folding_factor; num_rounds],
            log_inv_rates: (0..num_rounds)
                .map(|i| log_inv_rate + (i + 1) * (folding_factor - 1))
                .collect(),
            security_assumption,
            security_level,
            pow_bits,
        }
    }
}

/// A fully expanded FRI configuration.
#[derive(Clone)]
pub struct StirConfig {
    /// The configuration for the LDT desired.
    pub(crate) ldt_parameters: LowDegreeParameters,

    /// The security assumption under which STIR was configured.
    pub(crate) security_assumption: SecurityAssumption,

    /// The desired security level.
    pub(crate) security_level: usize,

    /// The maximum number of pow bits allowed (over and we throw a warning, as probably then we are misconfigured.)
    pub(crate) max_pow_bits: usize,

    /// The rate of the inital RS code used during the protocol.    
    pub(crate) starting_log_inv_rate: usize,

    /// The pow bits used in the batching phase.
    pub batching_pow_bits: f64,

    /// The initial folding factor.
    pub(crate) starting_folding_factor: usize,

    /// The initial domain size
    pub(crate) starting_domain_log_size: usize,

    /// The initial pow bits used in the first fold.
    pub(crate) starting_folding_pow_bits: f64,

    /// The round-specific parameters.
    pub(crate) round_parameters: Vec<RoundConfig>,

    /// Degree of the final polynomial sent over.
    pub(crate) final_poly_log_degree: usize,

    /// Number of queries in the last round
    pub(crate) final_queries: usize,

    /// Number of final bits of proof of work (for the queries).
    pub(crate) final_pow_bits: f64,

    /// Rate of the final RS codeword.
    pub(crate) final_log_inv_rate: usize,
}

/// Round specific configuration
#[derive(Debug, Clone)]
pub(crate) struct RoundConfig {
    /// Folding factor for this round.
    pub(crate) folding_factor: usize,
    /// Size of evaluation domain (of oracle sent in this round)
    pub(crate) evaluation_domain_log_size: usize,
    /// Number of bits of proof of work (for the queries).
    pub(crate) pow_bits: f64,
    /// Number of queries in this round
    pub(crate) num_queries: usize,
    /// Number of OOD samples in this round
    pub(crate) ood_samples: usize,
    /// Rate of current RS codeword
    pub(crate) log_inv_rate: usize,
}

impl StirConfig {
    /// Given a LDT parameter and some parameters for STIR, populate the config.
    pub fn new(ldt_parameters: LowDegreeParameters, stir_parameters: StirParameters) -> Self {
        // We need to fold at least some time
        assert!(
            stir_parameters.starting_folding_factor > 0
                && stir_parameters.folding_factors.iter().all(|&x| x > 0),
            "folding factors should be non zero"
        );
        assert_eq!(
            stir_parameters.folding_factors.len(),
            stir_parameters.log_inv_rates.len()
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
        let starting_folding_factor = stir_parameters.starting_folding_factor;
        let starting_domain_log_size =
            ldt_parameters.log_degree + stir_parameters.starting_log_inv_rate;

        let batching_pow_bits = if ldt_parameters.batch_size > 1 {
            // We now start, the initial folding pow bits
            pow_util(
                security_level,
                stir_parameters.security_assumption.prox_gaps_error(
                    ldt_parameters.log_degree,
                    stir_parameters.starting_log_inv_rate,
                    ldt_parameters.field.extension_bit_size(),
                    ldt_parameters.batch_size,
                ),
            )
        } else {
            0.
        };

        // Degree of next polynomial to send
        let mut current_log_degree = ldt_parameters.log_degree - starting_folding_factor;
        let mut log_inv_rate = stir_parameters.starting_log_inv_rate;

        // We now start, the initial folding pow bits
        let starting_folding_pow_bits = pow_util(
            security_level,
            stir_parameters.security_assumption.prox_gaps_error(
                current_log_degree,
                log_inv_rate,
                ldt_parameters.field.extension_bit_size(),
                1 << starting_folding_factor,
            ),
        );

        let mut round_parameters = Vec::with_capacity(num_rounds);

        for (folding_factor, next_rate) in stir_parameters
            .folding_factors
            .into_iter()
            .zip(stir_parameters.log_inv_rates)
        {
            // This is the size of the new evaluation domain
            let new_evaluation_domain_size = current_log_degree + next_rate;

            // Compute the ood samples required
            let ood_samples = stir_parameters.security_assumption.determine_ood_samples(
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

            let num_terms = num_queries + ood_samples;
            let prox_gaps_error_1 = stir_parameters.security_assumption.prox_gaps_error(
                current_log_degree,
                next_rate,
                ldt_parameters.field.extension_bit_size(),
                num_terms,
            );

            let prox_gaps_error_2 = stir_parameters.security_assumption.prox_gaps_error(
                current_log_degree - folding_factor,
                next_rate,
                ldt_parameters.field.extension_bit_size(),
                1 << folding_factor,
            );

            // Now compute the PoW
            let pow_bits = pow_util(
                security_level,
                query_error.min(prox_gaps_error_1).min(prox_gaps_error_2),
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
            batching_pow_bits,
            starting_folding_factor,
            starting_domain_log_size,
            starting_log_inv_rate: stir_parameters.starting_log_inv_rate,
            starting_folding_pow_bits,
            round_parameters,
            final_queries,
            final_pow_bits,
            final_poly_log_degree: final_log_degree,
            final_log_inv_rate: log_inv_rate,
        }
    }

    /// Given a configuration, simulate an execution, keeping track of which elements are sent.
    /// This is used to compute the proof size.
    pub fn build_proof(&self) -> Proof {
        let mut current_merkle_tree = MerkleTree::new(
            self.starting_domain_log_size - self.starting_folding_factor,
            self.ldt_parameters.field,
            (1 << self.starting_folding_factor) * self.ldt_parameters.batch_size,
            false, // First tree is over the base
        );

        let mut proof = Vec::with_capacity(self.round_parameters.len() + 1);

        for (round_number, r) in self.round_parameters.iter().enumerate() {
            let mut proof_elements = Vec::with_capacity(3);
            let next_merkle_tree = MerkleTree::new(
                r.evaluation_domain_log_size - r.folding_factor,
                self.ldt_parameters.field,
                1 << r.folding_factor,
                true,
            );

            // The merkle root
            proof_elements.push(ProofElement::MerkleRoot(next_merkle_tree));

            // The ood samples
            if r.ood_samples > 0 {
                proof_elements.push(ProofElement::FieldElements(FieldElements {
                    field: self.ldt_parameters.field,
                    num_elements: r.ood_samples,
                    is_extension: true,
                }));
            }

            // The queries
            proof_elements.push(ProofElement::MerkleQueries(MerkleQueries {
                merkle_tree: current_merkle_tree,
                num_openings: r.num_queries,
            }));

            proof.push(ProofRound {
                round_number,
                proof_elements,
            });

            current_merkle_tree = next_merkle_tree;
        }

        // The final queries
        proof.push(ProofRound {
            round_number: self.round_parameters.len(),
            proof_elements: vec![
                ProofElement::FieldElements(FieldElements {
                    field: self.ldt_parameters.field,
                    num_elements: 1 << self.final_poly_log_degree,
                    is_extension: true,
                }),
                ProofElement::MerkleQueries(MerkleQueries {
                    merkle_tree: current_merkle_tree,
                    num_openings: self.final_queries,
                }),
            ],
        });

        Proof(proof)
    }

    /// Prints a summary of the configuration for STIR.
    pub fn print_config_summary(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.ldt_parameters)?;
        writeln!(
            f,
            "Security level: {} bits using {} security and {} bits of PoW",
            self.security_level, self.security_assumption, self.max_pow_bits
        )?;

        writeln!(
            f,
            "Initial domain size: 2^{}, initial rate 2^-{}",
            self.starting_domain_log_size, self.starting_log_inv_rate,
        )?;

        if self.ldt_parameters.batch_size > 1 {
            writeln!(
                f,
                "Batch size: {}, batching_pow_bits: {:.1}",
                self.ldt_parameters.batch_size, self.batching_pow_bits
            )?;
        }

        writeln!(
            f,
            "Initial folding factor: {}, initial_folding_pow_bits: {:.1}",
            self.starting_folding_factor, self.starting_folding_pow_bits
        )?;
        for r in &self.round_parameters {
            r.fmt(f)?;
        }

        writeln!(
            f,
            "final_queries: {}, final polynomial: {}, final_rate: 2^-{}, final_pow_bits: {:.1}",
            self.final_queries,
            self.final_poly_log_degree,
            self.final_log_inv_rate,
            self.final_pow_bits,
        )?;

        Ok(())
    }

    /// Displays the round-by-error analysis for the protocol.
    fn print_rbr_summary(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "------------------------------------")?;
        writeln!(f, "Round by round soundness analysis:")?;
        writeln!(f, "------------------------------------")?;

        // The batching error.
        if self.ldt_parameters.batch_size > 1 {
            let batching_prox_gaps_error = self.security_assumption.prox_gaps_error(
                self.ldt_parameters.log_degree,
                self.starting_log_inv_rate,
                self.ldt_parameters.field.extension_bit_size(),
                self.ldt_parameters.batch_size,
            );

            writeln!(
                f,
                "{:.1} bits -- batch prox gaps: {:.1}, pow: {:.1}",
                batching_prox_gaps_error + self.batching_pow_bits,
                batching_prox_gaps_error,
                self.batching_pow_bits,
            )?;
        }

        let mut current_log_degree = self.ldt_parameters.log_degree - self.starting_folding_factor;
        let mut log_inv_rate = self.starting_log_inv_rate;

        let starting_prox_gaps_error = self.security_assumption.prox_gaps_error(
            current_log_degree,
            log_inv_rate,
            self.ldt_parameters.field.extension_bit_size(),
            1 << self.starting_folding_factor,
        );

        writeln!(
            f,
            "{:.1} bits -- prox gaps: {:.1}, pow: {:.1}",
            starting_prox_gaps_error + self.starting_folding_pow_bits,
            starting_prox_gaps_error,
            self.starting_folding_pow_bits,
        )?;

        for r in &self.round_parameters {
            let next_rate = r.evaluation_domain_log_size - current_log_degree;

            // OOD error
            if r.ood_samples > 0 {
                let ood_error = self.security_assumption.ood_error(
                    current_log_degree,
                    next_rate,
                    self.ldt_parameters.field.extension_bit_size(),
                    r.ood_samples,
                );

                writeln!(f, "{:.1} bits -- OOD sample", ood_error)?;
            }

            // STIR error
            let query_error = self
                .security_assumption
                .queries_error(log_inv_rate, r.num_queries);

            let prox_gaps_error_1 = self.security_assumption.prox_gaps_error(
                current_log_degree,
                next_rate,
                self.ldt_parameters.field.extension_bit_size(),
                r.num_queries + r.ood_samples,
            );

            let prox_gaps_error_2 = self.security_assumption.prox_gaps_error(
                current_log_degree - r.folding_factor,
                next_rate,
                self.ldt_parameters.field.extension_bit_size(),
                1 << r.folding_factor,
            );

            writeln!(
                f,
                "{:.1} bits -- query error: {:.1}, degree correction: {:.1}, folding error: {:.1}, pow: {:.1}",
                query_error.min(prox_gaps_error_1.min(prox_gaps_error_2)) + r.pow_bits,
                query_error,
                prox_gaps_error_1,
                prox_gaps_error_2,
                r.pow_bits,
            )?;

            current_log_degree -= r.folding_factor;
            log_inv_rate = next_rate;
        }

        let final_query_error = self
            .security_assumption
            .queries_error(log_inv_rate, self.final_queries);

        writeln!(
            f,
            "{:.1} bits -- query error: {:.1}, pow: {:.1}",
            final_query_error + self.final_pow_bits,
            final_query_error,
            self.final_pow_bits
        )?;

        Ok(())
    }
}

impl Display for StirConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.print_config_summary(f)?;
        self.print_rbr_summary(f)?;
        writeln!(f, "{}", self.build_proof())
    }
}

impl Display for RoundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Folding factor: {}, domain_size: 2^{}, num_queries: {}, rate: 2^-{}, pow_bits: {:.1}, ood_samples: {}",
            self.folding_factor, self.evaluation_domain_log_size, self.num_queries, self.log_inv_rate, self.pow_bits, self.ood_samples,
        )
    }
}

// TODO: Maybe dedup
fn pow_util(security_level: usize, error: f64) -> f64 {
    0f64.max(security_level as f64 - error)
}
