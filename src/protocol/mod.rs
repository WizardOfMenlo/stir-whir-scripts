pub mod builder;
pub mod proof_size;

use std::fmt;

use proof_size::ProofElement;

use crate::utils::{display_size, pretty_print_float_slice};

/// A struct representing a cryptographic protocol.
///
/// The `Protocol` struct contains information about a cryptographic protocol,
/// including its name, the size of digest being used, proof sizes and round by round soundness.
///
/// # Attributes
/// - `protocol_name`: A `String` representing the name of the protocol.
/// - `digest_size_bits`: A `usize` indicating the size of the digest in bits.
/// - `rounds`: A `Vec<Round>` containing the rounds involved in the protocol.
#[derive(Debug, Clone)]
pub struct Protocol {
    /// The name of the protocol.
    protocol_name: String,

    /// The size of the digest in bits.
    digest_size_bits: usize,

    /// The rounds involved in the protocol.
    rounds: Vec<Round>,
}

impl Protocol {
    /// Compose two protocols together
    pub fn chain(mut self, other: Protocol) -> Self {
        assert_eq!(self.digest_size_bits, other.digest_size_bits);
        self.protocol_name = format!("{} <> {}", self.protocol_name, other.protocol_name);
        self.rounds.extend(other.rounds);
        self
    }

    /// Calculates the proof size in bits of the protocol
    pub fn proof_size_bits(&self) -> usize {
        self.rounds
            .iter()
            .flat_map(|round| {
                // Iterate over each message in the round
                round.messages.iter().filter_map(|message| {
                    // Check if the message is a ProverMessage
                    if let Message::ProverMessage(prover_message) = message {
                        // If it is, return the size in bits of the element
                        Some(prover_message.element.size_bits())
                    } else {
                        // Otherwise, return None
                        None
                    }
                })
            })
            // Sum all the sizes in bits
            .sum()
    }

    /// Prints a display of the rounds of the protocol, including the proof size of
    /// each round, and the descriptions of the components.
    pub fn print_size_summary(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Protocol {}", self.protocol_name)?;
        for round in &self.rounds {
            writeln!(f, "Round: {}", round.name)?;
            for message in &round.messages {
                if let Message::ProverMessage(prover_message) = message {
                    writeln!(
                        f,
                        "  {}: {}",
                        prover_message.element.element_type(),
                        display_size(prover_message.element.size_bits())
                    )?;
                }
            }
        }
        writeln!(
            f,
            "Total Proof Size: {}",
            display_size(self.proof_size_bits())
        )
    }

    /// Prints a summary of the round-by-errors in each round of the protocol.
    pub fn print_rbr_summary(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Protocol {}", self.protocol_name)?;
        for round in &self.rounds {
            writeln!(f, "Round: {}", round.name)?;
            for message in &round.messages {
                if let Message::VerifierMessage(verifier_message) = message {
                    writeln!(f, "  Total RBR Error: {:.1}", verifier_message.rbr_error())?;
                    for rbr_error in &verifier_message.rbr_errors {
                        writeln!(f, "    - {}: {:.1}", rbr_error.name, rbr_error.error)?;
                    }
                    writeln!(f, "    + pow_bits: {:.1}", verifier_message.pow_bits)?;
                }
            }
        }
        write!(f, "RbR vector: ")?;
        pretty_print_float_slice(f, &self.rbr_errors())
    }

    /// Returns the vector of round by round errors of the protocol.
    pub fn rbr_errors(&self) -> Vec<f64> {
        self.rounds
            .iter()
            .flat_map(|round| {
                round.messages.iter().filter_map(|message| {
                    if let Message::VerifierMessage(verifier_message) = message {
                        Some(verifier_message.rbr_error())
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    /// Returns the overall round-by-round knowledge soundness of the protocol.
    pub fn rbr_error(&self) -> f64 {
        *self
            .rbr_errors()
            .iter()
            .min_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap()
    }

    /// Computes the bits of security of the protocol against an adversary performing 2^log_ro_queries classical queries to the ROM.
    pub fn compiled_classical_security(&self, log_ro_queries: usize) -> f64 {
        let log_ro_queries = log_ro_queries as f64;
        let min_error = self.rbr_error();

        // State restoration error
        // Thm 31.3.1 from [CY24] (discounting the +k terms as the number of rounds is
        // much smaller than then num of queries)
        let state_restoration_error = min_error - log_ro_queries;

        // Thm 26.1.1 from [CY24] (assuming that 6 * l * (log l + 1) <= t and taking min instead of summing to avoid precisions issue)
        state_restoration_error
            .min(self.digest_size_bits as f64 - ((3_f64).log2() + 2. * log_ro_queries))
    }

    /// Computes the bits of security of the protocol against an adversary performing 2^log_ro_queries quantum queries to the QROM.
    pub fn compiled_quantum_security(&self, log_ro_queries: usize) -> f64 {
        let log_ro_queries = log_ro_queries as f64;
        let min_error = self.rbr_error();

        // Thm 8.6 in 2019/834 (again taking min instead of summing)
        // NOTE: That thm only gives asymptotics and not concrete
        (min_error - 2. * log_ro_queries).min(self.digest_size_bits as f64 - (3. * log_ro_queries))
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.print_rbr_summary(f)?;
        self.print_size_summary(f)
    }
}

/// Represents a round of the protocol
/// NOTE: This groups a number of messages into a single round.
/// The number of rounds in a classical sense is obtained by counting the number of verifier messages.
#[derive(Debug, Clone)]
pub struct Round {
    name: String,
    messages: Vec<Message>,
}

/// A message exchanged in the protocol
#[derive(Debug, Clone)]
pub enum Message {
    ProverMessage(ProverMessage),
    VerifierMessage(VerifierMessage),
}

impl Message {
    pub fn is_prover_message(&self) -> bool {
        matches!(self, Message::ProverMessage(_))
    }

    pub fn is_verifier_message(&self) -> bool {
        matches!(self, Message::VerifierMessage(_))
    }
}

/// Represents a message sent from the prover to the verifier.
#[derive(Debug, Clone)]
pub struct ProverMessage {
    element: ProofElement,
}

impl ProverMessage {
    /// Creates a prover message
    pub fn new(element: ProofElement) -> Self {
        Self { element }
    }
}

/// Represents a message sent from the verifier to the prover.
#[derive(Debug, Clone)]
pub struct VerifierMessage {
    rbr_errors: Vec<RbRError>,
    pow_bits: f64,
}

impl VerifierMessage {
    /// Creates a verifier message
    pub fn new(rbr_errors: Vec<RbRError>, pow_bits: f64) -> Self {
        Self {
            rbr_errors,
            pow_bits,
        }
    }

    /// Computes the overall round-by-round error of this protocol
    pub fn rbr_error(&self) -> f64 {
        // Note this is actually improper, we are taking min instead of summing
        // to avoid losses in precisions.
        self.rbr_errors
            .iter()
            .map(|e| e.error)
            .min_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap()
            + self.pow_bits
    }
}

/// Represents a round-by-round error incurred by the protocol.
#[derive(Debug, Clone)]
pub struct RbRError {
    name: String,
    error: f64,
}

impl RbRError {
    pub fn new(name: &str, error: f64) -> Self {
        Self {
            name: name.to_string(),
            error,
        }
    }
}
