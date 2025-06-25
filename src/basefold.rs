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

/// Parameters parametrizing an instance of Basefold.
/// This does not include the entire configuration of Basefold, as we populate that later on according to required security config.
#[derive(Clone)]
pub struct BasefoldParameters {
    /// The starting rate used in the protocol.
    pub starting_log_inv_rate: usize,

    /// The folding factor in the first round.
    /// Given in log form, i.e. starting_folding_factor = 2 implies that the degree is reduced by a factor of 4.
    pub starting_folding_factor: usize,

    /// The folding factors in the remaining rounds.
    /// Given in log form, i.e. folding_factors[i] = 2 implies that the degree in round i is reduced by a factor of 4.
    pub folding_factors: Vec<usize>,

    /// The security assumption under which to configure Basefold.
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

impl BasefoldParameters {
    /// Instantiate a Basefold configuration where each round does a fixed amount of folding.
    pub fn fixed_folding(
        log_inv_rate: usize,
        folding_factor: usize,
        num_rounds: usize,
        security_assumption: SecurityAssumption,
        security_level: usize,
        pow_bits: usize,
        digest_size_bits: usize,
    ) -> Self {
        BasefoldParameters {
            starting_log_inv_rate: log_inv_rate,
            starting_folding_factor: folding_factor,
            folding_factors: vec![folding_factor; num_rounds],
            security_assumption,
            security_level,
            pow_bits,
            digest_size_bits,
        }
    }
}

/// The configuration and structure of the Basefold protocol.
#[derive(Debug, Clone)]
pub struct BasefoldProtocol {
    pub config: BasefoldConfig,
    pub protocol: Protocol,
}

impl BasefoldProtocol {
    /// Given a LDT parameter and some parameters for Basefold, populate the config.
    pub fn new(
        ldt_parameters: LowDegreeParameters,
        basefold_parameters: BasefoldParameters,
    ) -> Self {
        // We need to fold at least some time
        assert!(
            basefold_parameters.starting_folding_factor > 0
                && basefold_parameters.folding_factors.iter().all(|&x| x > 0),
            "folding factors should be non zero"
        );

        // We cannot fold too much
        let total_reduction = basefold_parameters.starting_folding_factor
            + basefold_parameters.folding_factors.iter().sum::<usize>();
        assert!(total_reduction <= ldt_parameters.log_degree);

        // If less, just send the damn polynomials
        assert!(ldt_parameters.log_degree >= basefold_parameters.folding_factors[0]);

        // Compute the number of rounds and the leftover
        let final_log_degree = ldt_parameters.log_degree - total_reduction;
        let num_rounds = basefold_parameters.folding_factors.len();

        // Compute the security level
        let security_level = basefold_parameters.security_level;
        let protocol_security_level =
            0.max(basefold_parameters.security_level - basefold_parameters.pow_bits);

        // Initial domain size (the trace domain)
        let starting_folding_factor = basefold_parameters.starting_folding_factor;
        let starting_domain_log_size =
            ldt_parameters.log_degree + basefold_parameters.starting_log_inv_rate;

        let mut protocol_builder =
            ProtocolBuilder::new("Basefold protocol", basefold_parameters.digest_size_bits);

        // Pow bits for the batching steps
        let mut batching_pow_bits = 0.;
        if ldt_parameters.batch_size > 1 {
            // We can't really batch non linear constraints
            assert!(ldt_parameters.constraint_degree <= 2);
            let prox_gaps_error_batching = basefold_parameters.security_assumption.prox_gaps_error(
                ldt_parameters.log_degree,
                basefold_parameters.starting_log_inv_rate,
                ldt_parameters.field.extension_bit_size(),
                ldt_parameters.batch_size,
            ); // we now start, the initial folding pow bits
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
        let starting_merkle_tree = MerkleTree::new(
            starting_domain_log_size - starting_folding_factor,
            ldt_parameters.field,
            (1 << starting_folding_factor) * ldt_parameters.batch_size,
            false, // first tree is over the base
        );
        let mut commitments = vec![starting_merkle_tree];

        // Degree of next polynomial to send
        let mut current_log_degree = ldt_parameters.log_degree;
        let mut starting_folding_pow_bits_vec = Vec::with_capacity(starting_folding_factor);
        protocol_builder = protocol_builder.start_round("initial_iteration");
        for _ in 0..starting_folding_factor {
            // we now start, the initial folding pow bits
            let prox_gaps_error = basefold_parameters.security_assumption.prox_gaps_error(
                current_log_degree - 1,
                basefold_parameters.starting_log_inv_rate,
                ldt_parameters.field.extension_bit_size(),
                2,
            );

            let sumcheck_error = basefold_parameters
                .security_assumption
                .constraint_folding_error(
                    current_log_degree,
                    basefold_parameters.starting_log_inv_rate,
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
        protocol_builder = protocol_builder.end_round();

        let mut round_parameters = Vec::with_capacity(num_rounds);

        for folding_factor in basefold_parameters.folding_factors.into_iter() {
            let new_evaluation_domain_size =
                current_log_degree + basefold_parameters.starting_log_inv_rate;

            // Send the new oracle
            let current_merkle_tree = MerkleTree::new(
                new_evaluation_domain_size - folding_factor,
                ldt_parameters.field,
                1 << folding_factor,
                true,
            );
            protocol_builder = protocol_builder
                .start_round("basefold_iteration")
                .prover_message(ProverMessage::new(ProofElement::MerkleRoot(
                    current_merkle_tree,
                )));
            commitments.push(current_merkle_tree);

            let mut pow_bits_vec = Vec::with_capacity(folding_factor);
            for _ in 0..folding_factor {
                // we now start, the initial folding pow bits
                let prox_gaps_error = basefold_parameters.security_assumption.prox_gaps_error(
                    current_log_degree - 1,
                    basefold_parameters.starting_log_inv_rate,
                    ldt_parameters.field.extension_bit_size(),
                    2,
                );

                let sumcheck_error = basefold_parameters
                    .security_assumption
                    .constraint_folding_error(
                        current_log_degree,
                        basefold_parameters.starting_log_inv_rate,
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

                pow_bits_vec.push(starting_folding_pow_bits);
                current_log_degree -= 1;
            }
            protocol_builder = protocol_builder.end_round();

            let round_config = RoundConfig {
                evaluation_domain_log_size: new_evaluation_domain_size,
                folding_factor,
                folding_pow_bits: pow_bits_vec,
            };
            round_parameters.push(round_config);
        }

        // Compute the number of queries required
        let final_queries = basefold_parameters.security_assumption.queries(
            protocol_security_level,
            basefold_parameters.starting_log_inv_rate,
        );

        // We need to compute the errors, to compute the according PoW
        let query_error = basefold_parameters
            .security_assumption
            .queries_error(basefold_parameters.starting_log_inv_rate, final_queries);

        // Now compute the PoW
        let final_pow_bits = pow_util(security_level, query_error);

        protocol_builder = protocol_builder
            .start_round("query_round")
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
            )));

        for current_merkle_tree in commitments {
            // The queries
            protocol_builder = protocol_builder.prover_message(ProverMessage::new(
                ProofElement::MerkleQueries(MerkleQueries {
                    merkle_tree: current_merkle_tree,
                    num_openings: final_queries,
                }),
            ));
        }

        BasefoldProtocol {
            config: BasefoldConfig {
                ldt_parameters,
                security_assumption: basefold_parameters.security_assumption,
                security_level,
                max_pow_bits: basefold_parameters.pow_bits,
                batching_pow_bits,
                starting_folding_factor,
                starting_domain_log_size,
                log_inv_rate: basefold_parameters.starting_log_inv_rate,
                starting_folding_pow_bits: starting_folding_pow_bits_vec,
                round_parameters,
                queries: final_queries,
                pow_bits: final_pow_bits,
                final_poly_log_degree: final_log_degree,
            },
            protocol: protocol_builder.end_round().build(),
        }
    }
}

impl Display for BasefoldProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.config.fmt(f)?;
        self.protocol.fmt(f)
    }
}

/// A fully expanded Basefold configuration.
#[derive(Debug, Clone)]
pub struct BasefoldConfig {
    /// The configuration for the LDT desired.
    pub ldt_parameters: LowDegreeParameters,

    /// The security assumption under which Basefold was configured.
    pub security_assumption: SecurityAssumption,

    /// The desired security level.
    pub security_level: usize,

    /// The maximum number of pow bits allowed (over and we throw a warning, as probably then we are misconfigured.)
    pub max_pow_bits: usize,

    /// The rate of the RS codes used during the protocol.    
    pub log_inv_rate: usize,

    /// The pow bits used in the batching phase.
    pub batching_pow_bits: f64,

    /// The initial folding factor.
    pub starting_folding_factor: usize,
    /// The initial domain size
    pub starting_domain_log_size: usize,
    /// The initial pow bits used in the first fold.
    pub starting_folding_pow_bits: Vec<f64>,

    /// The round-specific parameters.
    pub round_parameters: Vec<RoundConfig>,

    /// Degree of the final polynomial sent over.
    pub final_poly_log_degree: usize,

    /// Number of Basefold queries
    pub queries: usize,

    /// Number of bits of proof of work (for the queries).
    pub pow_bits: f64,
}

/// Round specific configuration
#[derive(Debug, Clone)]
pub struct RoundConfig {
    /// Folding factor for this round.
    pub folding_factor: usize,
    /// Size of evaluation domain.
    pub evaluation_domain_log_size: usize,
    /// Number of folding pow_bits.
    pub folding_pow_bits: Vec<f64>,
}

impl BasefoldConfig {
    // Prints a summary of the configuration for Basefold.
    pub fn print_config_summary(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.ldt_parameters)?;
        writeln!(
            f,
            "Security level: {} bits using {} security and {} bits of PoW",
            self.security_level, self.security_assumption, self.max_pow_bits
        )?;

        writeln!(
            f,
            "Initial domain size: 2^{}, initial rate 2^-{}, queries: {}, pow_bits: {:.1}",
            self.starting_domain_log_size, self.log_inv_rate, self.queries, self.pow_bits
        )?;

        if self.ldt_parameters.batch_size > 1 {
            writeln!(
                f,
                "Batch size: {}, batching_pow_bits: {:.1}",
                self.ldt_parameters.batch_size, self.batching_pow_bits
            )?;
        }

        write!(
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
            "final_queries: {}, final polynomial: {}",
            self.queries, self.final_poly_log_degree,
        )?;

        Ok(())
    }
}

impl Display for BasefoldConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.print_config_summary(f)
    }
}

impl Display for RoundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Folding factor: {}, domain_size: 2^{}, folding_pow_bits: ",
            self.folding_factor, self.evaluation_domain_log_size,
        )?;
        pretty_print_float_slice(f, &self.folding_pow_bits)
    }
}
