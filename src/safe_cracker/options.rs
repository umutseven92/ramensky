//! Module containing the options that configure Ramensky, to use with `SafeCracker`.
//!
//! Default usage:
//! ```rust
//! use ramensky::safe_cracker::options::Options;
//! use ramensky::safe_cracker::safe_cracker::SafeCracker;
//! let safe_cracker = SafeCracker::build(Options::default()).unwrap();
//! ```
//!
//! Custom values:
//! ```rust
//! use ramensky::safe_cracker::brute_force_options::BruteForceOptions;
//! use ramensky::safe_cracker::common_pw_list_options::CommonPwListOptions;
//! use ramensky::safe_cracker::options::Options;
//! use ramensky::safe_cracker::safe_cracker::SafeCracker;
//! let safe_cracker = SafeCracker::build(Options::new(true, true, Some(CommonPwListOptions::default()), true, Some(BruteForceOptions::default()), None)).unwrap();

use crate::safe_cracker::brute_force_options::BruteForceOptions;
use crate::safe_cracker::common_pw_list_options::CommonPwListOptions;

pub struct Options<'a> {
    /// If `quiet` is true, no messages will be printed, like passwords being generated, elapsed time, or the password (if found).
    /// If disabled, make sure you are consuming the resulting [`PasswordCrackResult`](crate::safe_cracker::password_crack_result::PasswordCrackResult) correctly.
    pub quiet: bool,

    /// Whether to try the most common 10M passwords. This will be the first thing that runs.
    pub try_common_passwords: bool,

    /// Brute forcing options. Will only be used if ```try_brute_forcing``` is true.
    pub common_password_options: Option<CommonPwListOptions>,

    /// Whether to try to brute force the password. This will run last.
    pub try_brute_forcing: bool,

    /// Brute forcing options. Will only be used if ```try_brute_forcing``` is true.
    pub brute_forcing_options: Option<BruteForceOptions>,

    /// Path to a custom passwords list. If provided, this will run first.
    /// The password list file needs to be newline separated list of passwords.
    pub custom_pw_list_path: Option<&'a str>,
}

impl<'a> Options<'a> {
    pub fn new(
        quiet: bool,
        try_common_passwords: bool,
        common_password_options: Option<CommonPwListOptions>,
        try_brute_forcing: bool,
        brute_forcing_options: Option<BruteForceOptions>,
        custom_pw_list_path: Option<&'a str>,
    ) -> Self {
        Options {
            quiet,
            try_common_passwords,
            common_password_options,
            try_brute_forcing,
            brute_forcing_options,
            custom_pw_list_path,
        }
    }

    pub fn default() -> Self {
        Self::new(
            false,
            true,
            Some(CommonPwListOptions::default()),
            true,
            Some(BruteForceOptions::default()),
            None,
        )
    }
}
