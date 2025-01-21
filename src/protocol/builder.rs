use super::{proof_size::ProofElement, Message, Protocol, ProverMessage, Round, VerifierMessage};

pub struct ProtocolBuilder {
    protocol_name: String,
    digest_size_bits: usize,
    rounds: Vec<Round>,
    current_round: Option<RoundBuilder>,
}

impl ProtocolBuilder {
    pub fn new(name: &str, digest_size_bits: usize) -> Self {
        Self {
            protocol_name: name.to_owned(),
            digest_size_bits,
            rounds: Vec::new(),
            current_round: None,
        }
    }

    pub fn start_round(mut self, name: &str) -> Self {
        self.current_round = Some(RoundBuilder::new(name));
        self
    }

    pub fn prover_message(mut self, message: ProverMessage) -> Self {
        let digest_len = match message.element {
            ProofElement::MerkleRoot(mt) => mt.digest_size,
            ProofElement::MerkleQueries(mt_queries) => mt_queries.merkle_tree.digest_size,
            _ => self.digest_size_bits,
        };
        assert_eq!(
            digest_len, self.digest_size_bits,
            "Digest size does not match protocol's"
        );

        self.current_round
            .as_mut()
            .unwrap_or_else(|| panic!("No current round started"))
            .rounds
            .push(Message::ProverMessage(message));
        self
    }

    pub fn verifier_message(mut self, message: VerifierMessage) -> Self {
        self.current_round
            .as_mut()
            .unwrap_or_else(|| panic!("No current round started"))
            .rounds
            .push(Message::VerifierMessage(message));
        self
    }

    pub fn end_round(mut self) -> Self {
        if let Some(round_builder) = self.current_round.take() {
            self.rounds.push(round_builder.build());
        }
        self
    }

    pub fn build(self) -> Protocol {
        assert!(self.current_round.is_none(), "Round was not finalized");
        Protocol {
            protocol_name: self.protocol_name,
            digest_size_bits: self.digest_size_bits,
            rounds: self.rounds,
        }
    }
}

pub struct RoundBuilder {
    name: String,
    rounds: Vec<Message>,
}

impl RoundBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            rounds: Vec::new(),
        }
    }

    pub fn build(self) -> Round {
        assert!(!self.rounds.is_empty());
        Round {
            name: self.name,
            messages: self.rounds,
        }
    }
}
