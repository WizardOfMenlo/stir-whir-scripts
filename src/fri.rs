use std::fmt::Display;

use crate::{
    errors::SecurityAssumption,
    protocol::{
        builder::ProtocolBuilder,
        proof_size::{FieldElements, MerkleQueries, MerkleTree, ProofElement},
        Protocol, ProverMessage, RbRError, VerifierMessage,
    },
    utils::pow_util,
    LowDegreeParameters,
};

/// Parameters parametrizing an instance of FRI.
/// This does not include the entire configuration of FRI, as we populate that later on according to required security config.
#[derive(Clone)]
pub struct FriParameters {
    /// The starting rate used in the protocol.
    pub starting_log_inv_rate: usize,

    /// The folding factor in the first round.
    /// Given in log form, i.e. starting_folding_factor = 2 implies that the degree is reduced by a factor of 4.
    pub starting_folding_factor: usize,

    /// The folding factors in the remaining rounds.
    /// Given in log form, i.e. folding_factors[i] = 2 implies that the degree in round i is reduced by a factor of 4.
    pub folding_factors: Vec<usize>,

    /// The security assumption under which to configure FRI.
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

impl FriParameters {
    /// Instantiate a FRI configuration where each round does a fixed amount of folding.
    pub fn fixed_folding(
        log_inv_rate: usize,
        folding_factor: usize,
        num_rounds: usize,
        security_assumption: SecurityAssumption,
        security_level: usize,
        pow_bits: usize,
        digest_size_bits: usize,
    ) -> Self {
        FriParameters {
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

/// The configuration and structure of the FRI protocol.
#[derive(Debug, Clone)]
pub struct FriProtocol {
    pub config: FriConfig,
    pub protocol: Protocol,
}

impl FriProtocol {
    /// Given a LDT parameter and some parameters for FRI, populate the config.
    pub fn new(ldt_parameters: LowDegreeParameters, fri_parameters: FriParameters) -> Self {
        // We need to fold at least some time
        assert!(
            fri_parameters.starting_folding_factor > 0
                && fri_parameters.folding_factors.iter().all(|&x| x > 0),
            "folding factors should be non zero"
        );

        // We cannot fold too much
        let total_reduction = fri_parameters.starting_folding_factor
            + fri_parameters.folding_factors.iter().sum::<usize>();
        assert!(total_reduction <= ldt_parameters.log_degree);

        // If less, just send the damn polynomials
        assert!(ldt_parameters.log_degree >= fri_parameters.folding_factors[0]);

        // Compute the number of rounds and the leftover
        let final_log_degree = ldt_parameters.log_degree - total_reduction;
        let num_rounds = fri_parameters.folding_factors.len();

        // Compute the security level
        let security_level = fri_parameters.security_level;
        let protocol_security_level =
            0.max(fri_parameters.security_level - fri_parameters.pow_bits);

        // Initial domain size (the trace domain)
        let starting_folding_factor = fri_parameters.starting_folding_factor;
        let starting_domain_log_size =
            ldt_parameters.log_degree + fri_parameters.starting_log_inv_rate;

        let mut protocol_builder =
            ProtocolBuilder::new("FRI protocol", fri_parameters.digest_size_bits);

        // Pow bits for the batching steps
        let mut batching_pow_bits = 0.;
        if ldt_parameters.batch_size > 1 {
            let prox_gaps_error_batching = fri_parameters.security_assumption.prox_gaps_error(
                ldt_parameters.log_degree,
                fri_parameters.starting_log_inv_rate,
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
        let starting_merkle_tree = MerkleTree::new(
            starting_domain_log_size - starting_folding_factor,
            ldt_parameters.field,
            (1 << starting_folding_factor) * ldt_parameters.batch_size,
            false, // First tree is over the base
        );
        let mut commitments = vec![starting_merkle_tree];

        // Degree of next polynomial to send
        let mut current_log_degree = ldt_parameters.log_degree - starting_folding_factor;

        // We now start, the initial folding pow bits
        let starting_folding_prox_gaps_error = fri_parameters.security_assumption.prox_gaps_error(
            current_log_degree,
            fri_parameters.starting_log_inv_rate,
            ldt_parameters.field.extension_bit_size(),
            1 << starting_folding_factor,
        );
        let starting_folding_pow_bits = pow_util(security_level, starting_folding_prox_gaps_error);
        protocol_builder = protocol_builder
            .start_round("initial_iteration")
            .verifier_message(VerifierMessage::new(
                vec![RbRError::new(
                    "folding_error",
                    starting_folding_prox_gaps_error,
                )],
                starting_folding_pow_bits,
            ))
            .end_round();

        let mut round_parameters = Vec::with_capacity(num_rounds);

        for folding_factor in fri_parameters.folding_factors.into_iter() {
            let new_evaluation_domain_size =
                current_log_degree + fri_parameters.starting_log_inv_rate;

            // Send the new oracle
            let current_merkle_tree = MerkleTree::new(
                new_evaluation_domain_size - folding_factor,
                ldt_parameters.field,
                1 << folding_factor,
                true,
            );
            protocol_builder = protocol_builder
                .start_round("fri_iteration")
                .prover_message(ProverMessage::new(ProofElement::MerkleRoot(
                    current_merkle_tree,
                )));
            commitments.push(current_merkle_tree);

            let prox_gaps_error = fri_parameters.security_assumption.prox_gaps_error(
                current_log_degree - folding_factor,
                fri_parameters.starting_log_inv_rate,
                ldt_parameters.field.extension_bit_size(),
                1 << folding_factor,
            );

            // Now compute the PoW
            let pow_bits = pow_util(security_level, prox_gaps_error);

            protocol_builder = protocol_builder
                .verifier_message(VerifierMessage::new(
                    vec![RbRError::new("folding_error", prox_gaps_error)],
                    pow_bits,
                ))
                .end_round();

            let round_config = RoundConfig {
                evaluation_domain_log_size: new_evaluation_domain_size,
                folding_factor,
                folding_pow_bits: pow_bits,
            };
            round_parameters.push(round_config);

            current_log_degree -= folding_factor;
        }

        // Compute the number of queries required
        let final_queries = fri_parameters.security_assumption.queries(
            protocol_security_level,
            fri_parameters.starting_log_inv_rate,
        );

        // We need to compute the errors, to compute the according PoW
        let query_error = fri_parameters
            .security_assumption
            .queries_error(fri_parameters.starting_log_inv_rate, final_queries);

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

        FriProtocol {
            config: FriConfig {
                ldt_parameters,
                security_assumption: fri_parameters.security_assumption,
                security_level,
                max_pow_bits: fri_parameters.pow_bits,
                batching_pow_bits,
                starting_folding_factor,
                starting_domain_log_size,
                log_inv_rate: fri_parameters.starting_log_inv_rate,
                starting_folding_pow_bits,
                round_parameters,
                queries: final_queries,
                pow_bits: final_pow_bits,
                final_poly_log_degree: final_log_degree,
            },
            protocol: protocol_builder.end_round().build(),
        }
    }
}

impl Display for FriProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.config.fmt(f)?;
        self.protocol.fmt(f)
    }
}

/// A fully expanded FRI configuration.
#[derive(Debug, Clone)]
pub struct FriConfig {
    /// The configuration for the LDT desired.
    pub ldt_parameters: LowDegreeParameters,

    /// The security assumption under which FRI was configured.
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
    pub starting_folding_pow_bits: f64,

    /// The round-specific parameters.
    pub round_parameters: Vec<RoundConfig>,

    /// Degree of the final polynomial sent over.
    pub final_poly_log_degree: usize,

    /// Number of FRI queries
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
    pub folding_pow_bits: f64,
}

impl FriConfig {
    // Prints a summary of the configuration for FRI.
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
            "final_queries: {}, final polynomial: {}",
            self.queries, self.final_poly_log_degree,
        )?;

        Ok(())
    }
}

impl Display for FriConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.print_config_summary(f)
    }
}

impl Display for RoundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Folding factor: {}, domain_size: 2^{}, folding_pow_bits: {:.1}",
            self.folding_factor, self.evaluation_domain_log_size, self.folding_pow_bits,
        )
    }
}
