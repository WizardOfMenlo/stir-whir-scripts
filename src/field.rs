use std::fmt::Display;

#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub name: &'static str,
    pub field_size_bits: usize,
    pub extension_degree: usize,
}

pub const GOLDILOCKS_2: Field = Field {
    name: "Goldilocks",
    field_size_bits: 64,
    extension_degree: 2,
};

pub const BABYBEAR_5: Field = Field {
    name: "Goldilocks",
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
