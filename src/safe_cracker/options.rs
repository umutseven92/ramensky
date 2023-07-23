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
//! use ramensky::safe_cracker::options::Options;
//! use ramensky::safe_cracker::safe_cracker::SafeCracker;
//! let safe_cracker = SafeCracker::build(Options::new(true, true, false, None)).unwrap();

pub struct Options<'a> {
    /// If `quiet` is true, no messages will be printed, like passwords being generated, elapsed time, or the password (if found).
    /// If disabled, make sure you are consuming the resulting [`PasswordCrackResult`](crate::safe_cracker::password_crack_result::PasswordCrackResult) correctly.
    pub quiet: bool,

    /// Whether to try the most common 10M passwords. This will be the first thing that runs.
    pub try_common_passwords: bool,

    /// Whether to try to brute force the password. This will run last.
    pub try_brute_forcing: bool,

    /// Path to a custom passwords list. If provided, this will run first.
    /// The password list file needs to be newline separated list of passwords.
    custom_pw_list_path: Option<&'a str>,
}

impl<'a> Options<'a> {
    pub fn new(
        quiet: bool,
        try_common_passwords: bool,
        try_brute_forcing: bool,
        custom_pw_list_path: Option<&'a str>,
    ) -> Self {
        Options {
            quiet,
            try_common_passwords,
            try_brute_forcing,
            custom_pw_list_path,
        }
    }

    pub fn default() -> Self {
        Self::new(false, true, true, None)
    }
}
