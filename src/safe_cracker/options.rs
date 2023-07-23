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
//! let safe_cracker = SafeCracker::build(Options::new(true, true, false, false, None)).unwrap();

pub struct Options<'a> {
    /// If `quiet` is true, then intermediate information will not be printed (for example, the current password being tested).
    /// Beginning and end messages, including password (if found) and elapsed time will always be printed.
    pub quiet: bool,

    /// Whether to try the most common 10M passwords. This will be the first thing that runs.
    pub try_common_passwords: bool,

    /// Whether to try to brute force the password. This will run last.
    pub try_brute_forcing: bool,

    /// Whether to log execution information, like password (if found) and elapsed time.
    log: bool,

    /// Path to a custom passwords list. If provided, this will run first.
    /// The password list file needs to be newline separated list of passwords.
    custom_pw_list_path: Option<&'a str>,
}

impl<'a> Options<'a> {
    pub fn new(
        quiet: bool,
        try_common_passwords: bool,
        try_brute_forcing: bool,
        log: bool,
        custom_pw_list_path: Option<&'a str>,
    ) -> Self {
        Options {
            quiet,
            try_common_passwords,
            try_brute_forcing,
            log,
            custom_pw_list_path,
        }
    }

    pub fn default() -> Self {
        Self::new(false, true, true, true, None)
    }
}
