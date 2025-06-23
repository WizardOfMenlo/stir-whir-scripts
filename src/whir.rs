use std::fmt::Display;

use crate::{
    errors::SecurityAssumption,
    protocol::{
        builder::ProtocolBuilder,
        proof_size::{FieldElements, MerkleQueries, MerkleTree, ProofElement},
        Protocol, ProverMessage, RbRError, VerifierMessage,
    },
    utils::{pow_util, pretty_print_float_slice},
    LowDegreeParameters,
};

/// Parameters parametrizing an instance of WHIR.
/// This does not include the entire configuration of WHIR, as we populate that later on according to required security config.#[derive(Clone)]
pub struct WhirParameters {
    /// The starting rate used in the protocol.
    pub starting_log_inv_rate: usize,

    /// The folding factor in the first round.
    /// Given in log form, i.e. starting_folding_factor = 2 implies that the degree is reduced by a factor of 4.
    pub starting_folding_factor: usize,

    /// The folding factors in the remaining rounds.
    /// Given in log form, i.e. folding_factors[i] = 2 implies that the degree in round i is reduced by a factor of 4.
    pub folding_factors: Vec<usize>,

    /// The rates used in the internal rounds of WHIR.
    pub log_inv_rates: Vec<usize>,

    /// The security assumption under which to configure WHIR.
    pub security_assumption: SecurityAssumption,

    /// The security level desired.
    pub security_level: usize,

    /// The number of pow bits to use to reduce query error.
    /// Traditionally called also "grinding".
    /// NOTE: This does not affect the pow bits used to reduce proximity gaps errors.
    pub pow_bits: usize,

    /// The size of the digest for the Merkle tree
    pub digest_size_bits: usize,
}

impl WhirParameters {
    /// Instantiates a WHIR configuration in which the rate is constant. This is a worse version of FRI.
    pub fn fixed_rate_folding(
        log_inv_rate: usize,
        folding_factor: usize,
        num_rounds: usize,
        security_assumption: SecurityAssumption,
        security_level: usize,
        pow_bits: usize,
        digest_size_bits: usize,
    ) -> Self {
        WhirParameters {
            starting_log_inv_rate: log_inv_rate,
            starting_folding_factor: folding_factor,
            folding_factors: vec![folding_factor; num_rounds],
            log_inv_rates: vec![log_inv_rate; num_rounds],
            security_assumption,
            security_level,
            digest_size_bits,
            pow_bits,
        }
    }

    /// A WHIR configuration in which the domain shrinks by (1/2) in each iteration while the degree shrinks by (1/2^folding_factor).
    /// This is the version presented in the WHIR paper.
    pub fn fixed_domain_shift(
        log_inv_rate: usize,
        folding_factor: usize,
        num_rounds: usize,
        security_assumption: SecurityAssumption,
        security_level: usize,
        pow_bits: usize,
        digest_size_bits: usize,
    ) -> Self {
        WhirParameters {
            starting_log_inv_rate: log_inv_rate,
            starting_folding_factor: folding_factor,
            folding_factors: vec![folding_factor; num_rounds],
            log_inv_rates: (0..num_rounds)
                .map(|i| log_inv_rate + (i + 1) * (folding_factor - 1))
                .collect(),
            security_assumption,
            digest_size_bits,
            security_level,
            pow_bits,
        }
    }
}

/// The configuration and structure of the WHIR protocol.
#[derive(Debug, Clone)]
pub struct WhirProtocol {
    pub config: WhirConfig,
    pub protocol: Protocol,
}

impl WhirProtocol {
    /// Given a LDT parameter and some parameters for WHIR, populate the config.
    pub fn new(ldt_parameters: LowDegreeParameters, whir_parameters: WhirParameters) -> Self {
        // We need to fold at least some time
        assert!(
            whir_parameters.starting_folding_factor > 0
                && whir_parameters.folding_factors.iter().all(|&x| x > 0),
            "folding factors should be non zero"
        );
        assert_eq!(
            whir_parameters.folding_factors.len(),
            whir_parameters.log_inv_rates.len()
        );

        // We cannot fold too much
        let total_reduction = whir_parameters.starting_folding_factor
            + whir_parameters.folding_factors.iter().sum::<usize>();
        assert!(total_reduction <= ldt_parameters.log_degree);

        // If less, just send the damn polynomials
        assert!(ldt_parameters.log_degree >= whir_parameters.folding_factors[0]);

        // Compute the number of rounds and the leftover
        let final_log_degree = ldt_parameters.log_degree - total_reduction;
        let num_rounds = whir_parameters.folding_factors.len();

        // Compute the security level
        let security_level = whir_parameters.security_level;
        let protocol_security_level =
            0.max(whir_parameters.security_level - whir_parameters.pow_bits);

        // Initial domain size (the trace domain)
        let starting_folding_factor = whir_parameters.starting_folding_factor;
        let starting_domain_log_size =
            ldt_parameters.log_degree + whir_parameters.starting_log_inv_rate;

        let mut protocol_builder =
            ProtocolBuilder::new("WHIR protocol", whir_parameters.digest_size_bits);

        // Pow bits for the batching steps
        let mut batching_pow_bits = 0.;
        if ldt_parameters.batch_size > 1 {
            let prox_gaps_error_batching = whir_parameters.security_assumption.prox_gaps_error(
                ldt_parameters.log_degree,
                whir_parameters.starting_log_inv_rate,
                ldt_parameters.field.extension_bit_size(),
                ldt_parameters.batch_size,
            ); // We now start, the initial folding pow bits
            batching_pow_bits = pow_util(security_level, prox_gaps_error_batching);

            // Add the round for the batching
            protocol_builder = protocol_builder
                .start_round("batching_round")
                .verifier_message(VerifierMessage::new(
                    vec![RbRError::new("batching_error", prox_gaps_error_batching)],
                    batching_pow_bits,
                ))
                .end_round();
        }

        // Merkle tree committed to
        let mut current_merkle_tree = MerkleTree::new(
            starting_domain_log_size - starting_folding_factor,
            ldt_parameters.field,
            (1 << starting_folding_factor) * ldt_parameters.batch_size,
            false, // First tree is over the base
        );

        // Degree of next polynomial to send
        let mut current_log_degree = ldt_parameters.log_degree;
        let mut log_inv_rate = whir_parameters.starting_log_inv_rate;

        let mut starting_folding_pow_bits_vec =
            Vec::with_capacity(whir_parameters.starting_folding_factor);

        protocol_builder = protocol_builder.start_round("whir_iteration");
        for _ in 0..whir_parameters.starting_folding_factor {
            // We now start, the initial folding pow bits
            let prox_gaps_error = whir_parameters.security_assumption.prox_gaps_error(
                current_log_degree - 1,
                log_inv_rate,
                ldt_parameters.field.extension_bit_size(),
                1 << starting_folding_factor,
            );

            let sumcheck_error = whir_parameters
                .security_assumption
                .constraint_folding_error(
                    current_log_degree,
                    log_inv_rate,
                    ldt_parameters.field.extension_bit_size(),
                    ldt_parameters.constraint_degree,
                );

            let starting_folding_pow_bits =
                pow_util(security_level, prox_gaps_error.min(sumcheck_error));

            protocol_builder = protocol_builder
                .prover_message(ProverMessage::new(ProofElement::FieldElements(
                    FieldElements {
                        field: ldt_parameters.field,
                        num_elements: ldt_parameters.constraint_degree + 1,
                        is_extension: true,
                    },
                )))
                .verifier_message(VerifierMessage::new(
                    vec![
                        RbRError::new("folding_error", prox_gaps_error),
                        RbRError::new("sumcheck_error", sumcheck_error),
                    ],
                    starting_folding_pow_bits,
                ));

            starting_folding_pow_bits_vec.push(starting_folding_pow_bits);
            current_log_degree -= 1;
        }
        //protocol_builder = protocol_builder.end_round();

        let mut round_parameters = Vec::with_capacity(num_rounds);

        for (i, (folding_factor, next_rate)) in whir_parameters
            .folding_factors
            .into_iter()
            .zip(whir_parameters.log_inv_rates)
            .enumerate()
        {
            // This is the size of the new evaluation domain
            let new_evaluation_domain_size = current_log_degree + next_rate;

            // Send the new oracle
            let next_merkle_tree = MerkleTree::new(
                new_evaluation_domain_size - folding_factor,
                ldt_parameters.field,
                1 << folding_factor,
                true,
            );
            protocol_builder = protocol_builder
                //.start_round("stir_iteration")
                .prover_message(ProverMessage::new(ProofElement::MerkleRoot(
                    next_merkle_tree,
                )));

            // Compute the ood samples required
            let ood_samples = whir_parameters.security_assumption.determine_ood_samples(
                security_level,
                current_log_degree,
                next_rate,
                ldt_parameters.field.extension_bit_size(),
            );

            // Add OOD rounds to protocol
            if ood_samples > 0 {
                let ood_error = whir_parameters.security_assumption.ood_error(
                    current_log_degree,
                    next_rate,
                    ldt_parameters.field.extension_bit_size(),
                    ood_samples,
                );

                protocol_builder = protocol_builder
                    .verifier_message(VerifierMessage::new(
                        vec![RbRError::new("ood_error", ood_error)],
                        0.,
                    ))
                    .prover_message(ProverMessage::new(ProofElement::FieldElements(
                        FieldElements {
                            field: ldt_parameters.field,
                            num_elements: ood_samples,
                            is_extension: true,
                        },
                    )));
            }

            // Compute the number of queries required
            let num_queries = whir_parameters
                .security_assumption
                .queries(protocol_security_level, log_inv_rate);

            // We need to compute the errors, to compute the according PoW
            let query_error = whir_parameters
                .security_assumption
                .queries_error(log_inv_rate, num_queries);

            let num_terms = num_queries + ood_samples;
            let batching_error = whir_parameters
                .security_assumption
                .constraint_folding_error(
                    current_log_degree,
                    log_inv_rate,
                    ldt_parameters.field.extension_bit_size(),
                    num_terms,
                );

            // Now compute the PoW
            let pow_bits = pow_util(security_level, query_error.min(batching_error));

            protocol_builder = protocol_builder
                .verifier_message(VerifierMessage::new(
                    vec![
                        RbRError::new("query_error", query_error),
                        RbRError::new("batching_error", batching_error),
                    ],
                    pow_bits,
                ))
                .prover_message(ProverMessage::new(ProofElement::MerkleQueries(
                    MerkleQueries {
                        merkle_tree: current_merkle_tree,
                        num_openings: num_queries,
                    },
                )))
                .end_round();

            protocol_builder = protocol_builder.start_round(if i != num_rounds - 1 {
                "whir_iteration"
            } else {
                "final_sumcheck"
            });

            let mut pow_bits_vec = Vec::with_capacity(folding_factor);
            for _ in 0..folding_factor {
                // We now start, the initial folding pow bits
                let prox_gaps_error = whir_parameters.security_assumption.prox_gaps_error(
                    current_log_degree - 1,
                    next_rate,
                    ldt_parameters.field.extension_bit_size(),
                    2,
                );

                let sumcheck_error = whir_parameters
                    .security_assumption
                    .constraint_folding_error(
                        current_log_degree,
                        next_rate,
                        ldt_parameters.field.extension_bit_size(),
                        ldt_parameters.constraint_degree.max(2),
                    );

                let starting_folding_pow_bits =
                    pow_util(security_level, prox_gaps_error.min(sumcheck_error));

                protocol_builder = protocol_builder
                    .prover_message(ProverMessage::new(ProofElement::FieldElements(
                        FieldElements {
                            field: ldt_parameters.field,
                            num_elements: ldt_parameters.constraint_degree + 1,
                            is_extension: true,
                        },
                    )))
                    .verifier_message(VerifierMessage::new(
                        vec![
                            RbRError::new("folding_error", prox_gaps_error),
                            RbRError::new("sumcheck_error", sumcheck_error),
                        ],
                        starting_folding_pow_bits,
                    ));

                pow_bits_vec.push(starting_folding_pow_bits);
                current_log_degree -= 1;
            }
            let round_config = RoundConfig {
                evaluation_domain_log_size: new_evaluation_domain_size,
                folding_factor,
                num_queries,
                pow_bits: pow_bits_vec,
                ood_samples,
                log_inv_rate,
            };
            round_parameters.push(round_config);

            current_merkle_tree = next_merkle_tree;
            log_inv_rate = next_rate;
        }
        protocol_builder = protocol_builder.end_round();

        // Compute the number of queries required
        let final_queries = whir_parameters
            .security_assumption
            .queries(protocol_security_level, log_inv_rate);

        // We need to compute the errors, to compute the according PoW
        let query_error = whir_parameters
            .security_assumption
            .queries_error(log_inv_rate, final_queries);

        // Now compute the PoW
        let final_pow_bits = pow_util(security_level, query_error);

        // Add the final round message
        protocol_builder = protocol_builder
            .start_round("final_round")
            .verifier_message(VerifierMessage::new(
                vec![RbRError::new("query_error", query_error)],
                final_pow_bits,
            ))
            .prover_message(ProverMessage::new(ProofElement::FieldElements(
                FieldElements {
                    field: ldt_parameters.field,
                    num_elements: 1 << final_log_degree,
                    is_extension: true,
                },
            )))
            .prover_message(ProverMessage::new(ProofElement::MerkleQueries(
                MerkleQueries {
                    merkle_tree: current_merkle_tree,
                    num_openings: final_queries,
                },
            )))
            .end_round();

        WhirProtocol {
            config: WhirConfig {
                ldt_parameters,
                security_assumption: whir_parameters.security_assumption,
                security_level,
                max_pow_bits: whir_parameters.pow_bits,
                batching_pow_bits,
                starting_folding_factor,
                starting_domain_log_size,
                starting_log_inv_rate: whir_parameters.starting_log_inv_rate,
                starting_folding_pow_bits: starting_folding_pow_bits_vec,
                round_parameters,
                final_queries,
                final_pow_bits,
                final_poly_log_degree: final_log_degree,
                final_log_inv_rate: log_inv_rate,
            },
            protocol: protocol_builder.build(),
        }
    }
}

impl Display for WhirProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.config.fmt(f)?;
        self.protocol.fmt(f)
    }
}

/// A fully expanded WHIR configuration.
#[derive(Debug, Clone)]
pub struct WhirConfig {
    /// The configuration for the LDT desired.
    pub(crate) ldt_parameters: LowDegreeParameters,

    /// The security assumption under which WHIR was configured.
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
    pub(crate) starting_folding_pow_bits: Vec<f64>,

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
    pub(crate) pow_bits: Vec<f64>,
    /// Number of queries in this round
    pub(crate) num_queries: usize,
    /// Number of OOD samples in this round
    pub(crate) ood_samples: usize,
    /// Rate of current RS codeword
    pub(crate) log_inv_rate: usize,
}

impl WhirConfig {
    /// Prints a summary of the configuration for WHIR.
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
            "Initial folding factor: {}, initial_folding_pow_bits: ",
            self.starting_folding_factor,
        )?;
        pretty_print_float_slice(f, &self.starting_folding_pow_bits)?;

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
}

impl Display for WhirConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.print_config_summary(f)
    }
}

impl Display for RoundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Folding factor: {}, domain_size: 2^{}, num_queries: {}, rate: 2^-{}, ood_samples: {}, pow_bits: ",
            self.folding_factor, self.evaluation_domain_log_size, self.num_queries, self.log_inv_rate, self.ood_samples,
        )?;
        pretty_print_float_slice(f, &self.pow_bits)
    }
}
