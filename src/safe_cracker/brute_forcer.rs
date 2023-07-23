use crate::safe_cracker::brute_force_options::BruteForceOptions;

pub struct BruteForcer {
    options: BruteForceOptions,
}

impl BruteForcer {
    pub fn new(options: BruteForceOptions) -> Self {
        Self { options }
    }
}
