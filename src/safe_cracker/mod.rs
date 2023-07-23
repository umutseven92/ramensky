//! Module for the password cracker.

pub mod brute_force_options;
pub mod brute_forcer; // Needs to be pub to be benchmarked.
pub mod options;
pub mod password_crack_result;
pub mod password_reader; // Needs to be pub to be benchmarked.
pub mod safe_cracker;
