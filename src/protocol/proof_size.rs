//! Misc utilities for computing proof size
use crate::field::Field;

/// A token which is part of the argument string
#[derive(Debug, Clone, Copy)]
pub enum ProofElement {
    /// A Merkle root
    MerkleRoot(MerkleTree),
    /// A list of queries to the Merkle tree (with corresponding authentication paths and openings)
    MerkleQueries(MerkleQueries),
    /// A list of field elements
    FieldElements(FieldElements),
}

impl ProofElement {
    pub fn element_type(&self) -> &'static str {
        match self {
            ProofElement::MerkleRoot(_) => "MerkleRoot",
            ProofElement::MerkleQueries(_) => "MerkleQueries",
            ProofElement::FieldElements(_) => "FieldElements",
        }
    }
}

impl ProofElement {
    /// Given a proof, compute the total number of bits.
    pub fn size_bits(&self) -> usize {
        match self {
            ProofElement::MerkleRoot(tree) => tree.digest_size,
            ProofElement::MerkleQueries(queries) => queries.estimate_size_bits(),
            ProofElement::FieldElements(elements) => elements.size_bits(),
        }
    }
}

/// Represents a Merkle tree
#[derive(Debug, Clone, Copy)]
pub struct MerkleTree {
    /// The elements in the leaf of the tree
    pub leaf: FieldElements,

    /// How deep the tree is (contains 2^tree_depth elements)
    pub tree_depth: usize,

    /// How large is the hash digest
    pub digest_size: usize,
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
            digest_size: 256, // TODO: We might change this based on security level
        }
    }
}

/// Represents the opening to a merkle tree
#[derive(Debug, Clone, Copy)]
pub struct MerkleQueries {
    /// The corresponding tree
    pub merkle_tree: MerkleTree,

    /// How many openings are requested
    pub num_openings: usize,
}

impl MerkleQueries {
    /// Computes the number of copath elements in an authentication path.
    /// Includes path pruning done to deduplicate and reduce proof size.
    pub fn copath_elements(&self) -> usize {
        let log_num_openings = (self.num_openings as f64).log2().ceil() as usize;

        self.num_openings * (self.merkle_tree.tree_depth - log_num_openings)
    }

    /// Computes the size of an authentication path.
    pub fn copath_size(&self) -> usize {
        // We either reveal the neighbouring leaf or its digest, depending on which is shorter
        self.num_openings
            * self
                .merkle_tree
                .leaf
                .size_bits()
                .min(self.merkle_tree.digest_size)
            + self.copath_elements() * self.merkle_tree.digest_size
    }

    /// Compute the size of an opening.
    pub fn opening_size(&self) -> usize {
        self.num_openings * self.merkle_tree.leaf.size_bits()
    }

    /// Computes the total size, includes the auth path and the opening.
    pub fn estimate_size_bits(&self) -> usize {
        self.copath_size() + self.opening_size()
    }
}

/// Represents a list of field elements
#[derive(Debug, Clone, Copy)]
pub struct FieldElements {
    /// The field used
    pub field: Field,

    /// How many elements (NOTE: not in log form)
    pub num_elements: usize,

    /// Whether these are extension or base field elements
    pub is_extension: bool,
}

impl FieldElements {
    fn size_bits(&self) -> usize {
        self.num_elements
            * if self.is_extension {
                self.field.extension_bit_size()
            } else {
                self.field.field_size_bits
            }
    }
}
