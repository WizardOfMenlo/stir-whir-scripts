use super::{Iteration, Protocol, ProverMessage, Round, VerifierMessage};

pub struct ProtocolBuilder {
    protocol_name: String,
    iterations: Vec<Iteration>,
}

impl ProtocolBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            protocol_name: name.to_owned(),
            iterations: Vec::new(),
        }
    }

    pub fn add_iteration(self, iteration: Iteration) -> Self {
        let mut new_self = self;
        new_self.iterations.push(iteration);
        new_self
    }

    pub fn build(self) -> Protocol {
        Protocol {
            protocol_name: self.protocol_name,
            iterations: self.iterations,
        }
    }
}

pub struct IterationBuilder {
    rounds: Vec<Round>,
}

impl IterationBuilder {
    pub fn new() -> Self {
        Self { rounds: Vec::new() }
    }

    pub fn add_round(mut self, round: Round) -> Self {
        self.rounds.push(round);
        self
    }

    pub fn build(self) -> Iteration {
        assert!(!self.rounds.is_empty());
        Iteration {
            rounds: self.rounds,
        }
    }
}

pub struct RoundBuilder {
    prover_message: Option<ProverMessage>,
    verifier_message: Option<VerifierMessage>,
}

impl RoundBuilder {
    pub fn new() -> Self {
        Self {
            prover_message: None,
            verifier_message: None,
        }
    }

    pub fn prover_message(mut self, prover_message: ProverMessage) -> Self {
        self.prover_message = Some(prover_message);
        self
    }

    pub fn verifier_message(mut self, verifier_message: VerifierMessage) -> Self {
        self.verifier_message = Some(verifier_message);
        self
    }

    pub fn build(self) -> Round {
        Round {
            prover_message: self.prover_message.expect("Prover message must be set"),
            verifier_message: self.verifier_message.expect("Verifier message must be set"),
        }
    }
}
