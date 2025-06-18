use std::fmt::Display;

use field::Field;

pub mod basefold;
pub mod errors;
pub mod field;
pub mod fri;
pub mod protocol;
pub mod stir;
pub(crate) mod utils;
pub mod whir;

/// Selects a default maximum number of PoW such that any values greater than it results in an error.
pub fn default_max_pow(num_variables: usize, log_inv_rate: usize) -> usize {
    num_variables + log_inv_rate - 3
}

/// The parameters for a (batched) low-degree test.
#[derive(Debug, Clone, Copy)]
pub struct LowDegreeParameters {
    /// The field the low degree test is over
    pub field: Field,
    /// The degree to be test
    pub log_degree: usize,
    /// How many functions are tested (NOTE: not in log form)
    pub batch_size: usize,
    /// The degree of constraints being proven on the committed words (0 for just proximity testing)
    pub constraint_degree: usize,
}

impl Display for LowDegreeParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Field: {}, Degree: 2^{}, batch_size: {}",
            self.field, self.log_degree, self.batch_size
        )
    }
}
