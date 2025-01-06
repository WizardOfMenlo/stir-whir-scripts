pub mod builder;
pub mod proof_size;

use proof_size::ProofElement;

#[derive(Debug, Clone)]
pub struct Protocol {
    protocol_name: String,
    iterations: Vec<Iteration>,
}

impl Protocol {
    pub fn proof_size_bits(&self) -> usize {
        self.iterations
            .iter()
            .flat_map(|iteration| &iteration.rounds)
            .flat_map(|round| &round.prover_message.elements)
            .map(|element| element.size_bits())
            .sum()
    }

    pub fn get_rbr_errors(&self) -> Vec<f64> {
        self.iterations
            .iter()
            .flat_map(|iteration| {
                iteration
                    .rounds
                    .iter()
                    .map(|round| round.verifier_message.rbr_error)
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct Iteration {
    rounds: Vec<Round>,
}

#[derive(Debug, Clone)]
pub struct Round {
    prover_message: ProverMessage,
    verifier_message: VerifierMessage,
}

#[derive(Debug, Clone)]
pub struct ProverMessage {
    elements: Vec<ProofElement>,
}

impl ProverMessage {
    pub fn new(elements: Vec<ProofElement>) -> Self {
        Self { elements }
    }

    pub fn new_single(element: ProofElement) -> Self {
        Self {
            elements: vec![element],
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifierMessage {
    rbr_error: f64,
}

impl VerifierMessage {
    pub fn new(rbr_error: f64) -> Self {
        Self { rbr_error }
    }
}
