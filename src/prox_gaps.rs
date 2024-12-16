use std::{fmt::Display, str::FromStr};

#[derive(Debug, Clone, Copy)]
pub enum ProxGapsType {
    // Use distance 1 - (1-rate)/2
    UniqueDecoding,

    // Use distance 1 - sqrt(rate)
    Johnson,

    // Use distance 1 - rate
    Capacity,
}

impl Display for ProxGapsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match &self {
                ProxGapsType::Johnson => "Johnson",
                ProxGapsType::Capacity => "Capacity",
                ProxGapsType::UniqueDecoding => "UniqueDecoding",
            }
        )
    }
}

impl FromStr for ProxGapsType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "Johnson" {
            Ok(ProxGapsType::Johnson)
        } else if s == "Capacity" {
            Ok(ProxGapsType::Capacity)
        } else if s == "UniqueDecoding" {
            Ok(ProxGapsType::UniqueDecoding)
        } else {
            Err(format!("Invalid soundness specification: {}", s))
        }
    }
}
