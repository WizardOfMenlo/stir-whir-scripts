//! Misc utilities for computing proof size

use std::fmt::Display;

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

/// A proof round contains the `ProofElement`s relating to this round.
#[derive(Debug, Clone)]
pub struct ProofRound {
    pub round_number: usize,
    pub proof_elements: Vec<ProofElement>,
}

/// A proof consists of a list of proof rounds.
#[derive(Debug, Clone)]
pub struct Proof(pub Vec<ProofRound>);

impl Proof {
    /// Given a proof, compute the total number of bits.
    pub fn total_size_bits(&self) -> usize {
        let mut res = 0;
        for r in &self.0 {
            for el in &r.proof_elements {
                res += match el {
                    ProofElement::MerkleRoot(tree) => tree.digest_size,
                    ProofElement::MerkleQueries(queries) => queries.estimate_size_bits(),
                    ProofElement::FieldElements(elements) => elements.size_bits(),
                };
            }
        }

        res
    }
}

fn display_size(bits: usize) -> String {
    if bits == 0 {
        return "0B".to_owned();
    }

    let size_bytes = bits as f64 / 8.;
    let size_name = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    let i = size_bytes.log(1024_f64).floor() as usize;
    let p = 1024_f64.powf(i as f64);
    let s = (size_bytes / p).round();

    format!("{} {}", s, size_name[i])
}

impl Display for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "------------------------------------")?;
        writeln!(f, "Proof breakdown:")?;
        writeln!(f, "------------------------------------")?;

        for r in &self.0 {
            writeln!(f, "Round {}", r.round_number)?;

            for element in &r.proof_elements {
                match element {
                    ProofElement::MerkleRoot(tree) => {
                        writeln!(f, "Merkle root: {}", display_size(tree.digest_size))?;
                    }
                    ProofElement::MerkleQueries(queries) => {
                        writeln!(
                            f,
                            "Openings {}, copaths: {}, leaves: {}, total: {}",
                            queries.num_openings,
                            display_size(queries.copath_size()),
                            display_size(queries.opening_size()),
                            display_size(queries.estimate_size_bits())
                        )?;
                    }
                    ProofElement::FieldElements(elems) => {
                        writeln!(
                            f,
                            "Field elements: {} over {}, total: {}",
                            elems.num_elements,
                            if elems.is_extension {
                                "extension"
                            } else {
                                "base"
                            },
                            display_size(elems.size_bits())
                        )?;
                    }
                }
            }
        }

        writeln!(
            f,
            "Total proof size: {}",
            display_size(self.total_size_bits())
        )
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
    fn copath_elements(&self) -> usize {
        let log_num_openings = (self.num_openings as f64).log2().ceil() as usize;

        self.num_openings * (self.merkle_tree.tree_depth - log_num_openings)
    }

    fn copath_size(&self) -> usize {
        // We either reveal the leaf or its digest, depending on which is shorter
        self.num_openings
            * self
                .merkle_tree
                .leaf
                .size_bits()
                .min(self.merkle_tree.digest_size)
            + self.copath_elements() * self.merkle_tree.digest_size
    }

    fn opening_size(&self) -> usize {
        self.num_openings * self.merkle_tree.leaf.size_bits()
    }

    fn estimate_size_bits(&self) -> usize {
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
