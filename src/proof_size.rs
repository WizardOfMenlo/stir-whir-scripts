// Misc utilities for computing proof size

use crate::field::Field;

#[derive(Debug, Clone, Copy)]
pub enum ProofElement {
    MerkleRoot(MerkleTree),
    MerkleQueries(MerkleQueries),
    FieldElements(FieldElements),
}

#[derive(Debug, Clone)]
pub struct ProofRound {
    pub round_number: usize,
    pub proof_elements: Vec<ProofElement>,
}

#[derive(Debug, Clone)]
pub struct Proof(pub Vec<ProofRound>);

#[derive(Debug, Clone, Copy)]
pub struct MerkleTree {
    leaf: FieldElements,
    tree_depth: usize,
    digest_size: usize,
}

impl MerkleTree {
    pub fn new(tree_depth: usize, field: Field, leaf_size: usize, is_extension: bool) -> Self {
        MerkleTree {
            leaf: FieldElements {
                field,
                num_elements: leaf_size,
                is_extension,
            },
            tree_depth,
            digest_size: 256,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MerkleQueries {
    pub merkle_tree: MerkleTree,
    pub num_openings: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct FieldElements {
    pub field: Field,
    pub num_elements: usize,
    pub is_extension: bool,
}
