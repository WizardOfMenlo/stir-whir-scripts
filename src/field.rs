use std::fmt::Display;

/// Field represents a field that we are working over.
#[derive(Debug, Clone, Copy)]
pub struct Field {
    /// The name of the field for displaying.
    pub name: &'static str,

    /// The size of the base field.
    pub field_size_bits: usize,

    /// The extension degree of the field (where we usually sample challenges from)
    pub extension_degree: usize,
}

/// The Goldilocks field, using a quadratic extension for security
pub const GOLDILOCKS_2: Field = Field {
    name: "Goldilocks",
    field_size_bits: 64,
    extension_degree: 2,
};

/// The BabyBear field, using a quintic extension for security
pub const BABYBEAR_5: Field = Field {
    name: "Babybear",
    field_size_bits: 27,
    extension_degree: 5,
};

impl Field {
    pub fn extension_bit_size(&self) -> usize {
        self.extension_degree * self.field_size_bits
    }
}

impl Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}-extension of {} - {} bits base",
            self.extension_degree, self.name, self.field_size_bits
        )
    }
}
