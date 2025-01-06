pub mod builder;
pub mod proof_size;

use proof_size::ProofElement;

#[derive(Debug, Clone)]
pub struct Protocol {
    protocol_name: String,
    rounds: Vec<Round>,
}

impl Protocol {
    pub fn proof_size_bits(&self) -> usize {
        self.rounds
            .iter()
            .flat_map(|round| {
                round.messages.iter().filter_map(|message| {
                    if let Message::ProverMessage(prover_message) = message {
                        Some(prover_message.element.size_bits())
                    } else {
                        None
                    }
                })
            })
            .sum()
    }

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
}

#[derive(Debug, Clone)]
pub struct Round {
    name: String,
    messages: Vec<Message>,
}

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

#[derive(Debug, Clone)]
pub struct ProverMessage {
    element: ProofElement,
}

impl ProverMessage {
    pub fn new(element: ProofElement) -> Self {
        Self { element }
    }
}

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

#[derive(Debug, Clone)]
pub struct VerifierMessage {
    rbr_errors: Vec<RbRError>,
    pow_bits: f64,
}

impl VerifierMessage {
    pub fn new(rbr_errors: Vec<RbRError>, pow_bits: f64) -> Self {
        Self {
            rbr_errors,
            pow_bits,
        }
    }
    pub fn rbr_error(&self) -> f64 {
        self.rbr_errors
            .iter()
            .map(|e| e.error)
            .min_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap()
            + self.pow_bits
    }
}
