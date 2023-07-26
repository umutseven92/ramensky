use std::error::Error;

const MAX_AMOUNT: usize = 10_000_000;

#[derive(Copy, Clone)]
pub struct CommonPwListOptions {
    /// How many of the common password list to use. The maximum amount is 10 million.
    /// Set as [`None`](Option::None) to use the whole list.
    pub amount_to_use: Option<usize>,
}

impl CommonPwListOptions {
    pub fn default() -> Self {
        Self::build(Some(1_000_000)).unwrap()
    }

    pub fn build(amount_to_use: Option<usize>) -> Result<Self, Box<dyn Error>> {
        if let Some(amount) = amount_to_use {
            if amount >= MAX_AMOUNT {
                return Err(format!(
                    "amount_to_use ({amount}) cannot be higher than {MAX_AMOUNT}."
                ))?;
            }
        }

        Ok(CommonPwListOptions { amount_to_use })
    }
}

#[cfg(test)]
mod tests {
    use crate::safe_cracker::common_pw_list_options::CommonPwListOptions;

    #[test]
    fn can_validate_amount() {
        assert!(CommonPwListOptions::build(Some(20_000_000)).is_err());
    }
}
