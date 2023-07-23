//! Module containing the options that configure how brute forcing step is done.

use std::error::Error;

#[derive(Copy, Clone)]
pub struct BruteForceOptions {
    /// Minimum size of the password being searched.
    pub minimum_size: usize,

    /// Maximum size of the password being searched.
    pub maximum_size: usize,

    /// Whether to include numbers in the search.
    pub include_numbers: bool,

    /// Whether to include ASCII characters in the search.
    pub include_characters: bool,

    /// Whether to include symbols in the search.
    pub include_symbols: bool,
}

impl BruteForceOptions {
    pub fn default() -> Self {
        Self::build(2, 10, true, true, false).unwrap()
    }

    pub fn build(
        minimum_size: usize,
        maximum_size: usize,
        include_numbers: bool,
        include_characters: bool,
        include_symbols: bool,
    ) -> Result<Self, Box<dyn Error>> {
        if minimum_size == maximum_size {
            return Err(format!(
                "minimum_size and maximum_size cannot be the same ({maximum_size})."
            ))?;
        }

        if minimum_size >= maximum_size {
            return Err(format!(
                "minimum_size ({minimum_size} cannot be bigger than maximum_size ({maximum_size})."
            ))?;
        }

        if include_numbers == false && include_symbols == false && include_characters == false {
            return Err(format!(
                "At least one of the include_* values (include_numbers, include_symbols, include_characters) need to be true."
            ))?;
        }

        Ok(BruteForceOptions {
            maximum_size,
            minimum_size,
            include_characters,
            include_numbers,
            include_symbols,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::safe_cracker::brute_force_options::BruteForceOptions;

    #[test]
    fn can_validate() {
        // Size validation
        assert!(BruteForceOptions::build(5, 5, true, true, true).is_err());
        assert!(BruteForceOptions::build(6, 3, true, true, true).is_err());
        assert!(BruteForceOptions::build(2, 8, true, true, true).is_ok());

        // include_* validation
        assert!(BruteForceOptions::build(2, 8, false, false, false).is_err());
        assert!(BruteForceOptions::build(2, 8, true, true, true).is_ok());
        assert!(BruteForceOptions::build(2, 8, true, false, true).is_ok());
    }
}
