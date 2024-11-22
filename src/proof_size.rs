// Misc utilities for computing proof size

use std::fmt::Display;

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

impl Proof {
    fn total_size_bits(&self) -> usize {
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

/*
def convert_size(size_bits):
    if size_bits == 0:
        return "0B"
    size_bytes = size_bits / 8
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])
    */

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
                        writeln!(f, "Merkle root: {}", display_size(tree.digest_size));
                    }
                    ProofElement::MerkleQueries(queries) => {
                        writeln!(
                            f,
                            "Openings {}, copaths: {}, leaves: {}, total: {}",
                            queries.num_openings,
                            display_size(queries.copath_size()),
                            display_size(queries.opening_size()),
                            display_size(queries.estimate_size_bits())
                        );
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
                        );
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

impl MerkleQueries {
    fn copath_elements(&self) -> usize {
        let log_num_openings = (self.num_openings as f64).log2().ceil() as usize;

        self.num_openings * (self.merkle_tree.tree_depth - log_num_openings)
    }

    fn copath_size(&self) -> usize {
        self.num_openings * self.merkle_tree.leaf.size_bits()
            + self.copath_elements() * self.merkle_tree.digest_size
    }

    fn opening_size(&self) -> usize {
        self.num_openings * self.merkle_tree.leaf.size_bits()
    }

    fn estimate_size_bits(&self) -> usize {
        self.copath_size() + self.opening_size()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FieldElements {
    pub field: Field,
    pub num_elements: usize,
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
