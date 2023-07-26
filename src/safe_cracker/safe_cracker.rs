//! Module containing the password cracker.

use std::error::Error;
use std::path::Path;
use std::time::Instant;

use crate::adaptor::attempt_result::AttemptResult;
use crate::adaptor::base::BaseAdaptor;
use crate::safe_cracker::brute_forcer::BruteForcer;
use crate::safe_cracker::options::Options;
use crate::safe_cracker::password_crack_result::PasswordCrackResult;
use crate::safe_cracker::password_reader::PasswordReader;
use crate::safe_cracker::reader_configuration::PwListConfiguration;

const COMMON_PW_PATH: &str = "resources/common-passwords.txt";

pub struct SafeCracker<'a> {
    password_reader: PasswordReader,
    brute_forcer: Option<BruteForcer>,
    options: Options<'a>,
}

impl<'a> SafeCracker<'a> {
    pub fn build(options: Options<'a>) -> Result<Self, Box<dyn Error>> {
        let mut paths = vec![];

        if options.try_common_passwords {
            if let Some(opt) = options.common_password_options {
                paths.push(PwListConfiguration::new(COMMON_PW_PATH, opt.amount_to_use));
            } else {
                return Err(
                    "common_password_options needs to set if try_common_passwords is enabled.",
                )?;
            }
        }

        if let Some(custom_path) = options.custom_pw_list_path {
            if !Path::new(custom_path).is_file() {
                return Err(format!(
                    "Custom password file path {custom_path} is not a valid file path."
                ))?;
            }
            paths.push(PwListConfiguration::new(COMMON_PW_PATH, None));
        }

        let brute_forcer;

        if options.try_brute_forcing {
            if let Some(opt) = options.brute_forcing_options {
                brute_forcer = Some(BruteForcer::new(opt));
            } else {
                return Err("brute_forcing_options needs to set if try_brute_forcing is enabled.")?;
            }
        } else {
            brute_forcer = None
        }

        Ok(Self {
            password_reader: PasswordReader::build(paths)?,
            brute_forcer,
            options,
        })
    }
    /// Start password cracking.
    /// This method will generate passwords, and call the adaptors `try_password()` method for each
    /// password.
    ///
    /// The execution order is:
    /// 1. Most common 10M passwords (skipped if not enabled in [Options](Options))
    /// 2. Custom password list (skipped if not provided in [Options](Options))
    /// 3. Brute forcing (skipped if not enabled in [Options](Options))
    ///
    /// Example usage:
    /// ```rust
    /// use ramensky::adaptor::custom::test_adaptor::TestAdaptor;
    /// use ramensky::adaptor::attempt_result::AttemptResult;
    /// use ramensky::safe_cracker::options::Options;
    /// use ramensky::safe_cracker::password_crack_result::PasswordCrackResult;
    /// use ramensky::safe_cracker::safe_cracker::SafeCracker;
    ///
    /// let safe_cracker = SafeCracker::build(Options::default()).unwrap();
    /// let adaptor = TestAdaptor::without_delay("abcde");
    /// match safe_cracker.start(adaptor).unwrap() {
    ///     PasswordCrackResult::Success(pw, elapsed) => println!("Success! Password is {pw}. Execution took {} seconds", elapsed.as_secs()),
    ///     PasswordCrackResult::Failure(elapsed) => println!("Failure. Execution took {} seconds", elapsed.as_secs()),
    /// }
    /// ```
    pub fn start<T: BaseAdaptor>(self, adaptor: T) -> Result<PasswordCrackResult, Box<dyn Error>> {
        macro_rules! print_with_ts {
            ($F:expr) => {
                if !self.options.quiet {
                    println!("{:?}\t{}", chrono::offset::Local::now(), $F);
                }
            };
        }

        print_with_ts!("Starting attempt");

        let now = Instant::now();

        for pw in self.password_reader {
            print_with_ts!(format!("Trying password {pw}"));

            let result = adaptor.try_password(&pw)?;

            match result {
                AttemptResult::Success => {
                    print_with_ts!(format!("Success! {pw} is the password."));
                    print_with_ts!(format!(
                        "Execution took {} seconds.",
                        now.elapsed().as_secs()
                    ));

                    return Ok(PasswordCrackResult::Success(pw, now.elapsed()));
                }
                AttemptResult::Failure => continue,
            }
        }

        print_with_ts!("Failure! Could not find the password.");
        print_with_ts!(format!(
            "Execution took {} seconds.",
            now.elapsed().as_secs()
        ));
        Ok(PasswordCrackResult::Failure(now.elapsed()))
    }
}

#[cfg(test)]
mod tests {
    use crate::adaptor::custom::test_adaptor::TestAdaptor;
    use crate::safe_cracker::common_pw_list_options::CommonPwListOptions;
    use crate::safe_cracker::options::Options;
    use crate::safe_cracker::password_crack_result::PasswordCrackResult;
    use crate::safe_cracker::safe_cracker::SafeCracker;

    #[test]
    fn should_find_in_common_passwords() {
        let safe_cracker = SafeCracker::build(Options::new(
            true,
            true,
            Some(CommonPwListOptions::default()),
            false,
            None,
            None,
        ))
        .unwrap();

        // "qwerty" is the 4th item in the common passwords list.
        let adaptor = TestAdaptor::without_delay("qwerty");

        let result = safe_cracker.start(adaptor).unwrap();

        match result {
            PasswordCrackResult::Success(pw, _) => {
                assert_eq!(pw, "qwerty");
                assert!(true);
            }
            PasswordCrackResult::Failure(_) => assert!(false),
        }
    }

    #[test]
    fn should_validate_custom_list_path() {
        // Not existent path
        let custom_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/resources/pw-list-wrong.txt"
        );

        assert!(SafeCracker::build(Options::new(
            true,
            false,
            None,
            false,
            None,
            Some(custom_path)
        ))
        .is_err())
    }

    #[test]
    fn should_find_in_custom_list() {
        let custom_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/resources/pw-list.txt");
        let safe_cracker = SafeCracker::build(Options::new(
            true,
            false,
            None,
            false,
            None,
            Some(custom_path),
        ))
        .unwrap();

        // "test2" is contained in the custom password list.
        let adaptor = TestAdaptor::without_delay("test2");

        let result = safe_cracker.start(adaptor).unwrap();

        match result {
            PasswordCrackResult::Success(pw, _) => {
                assert_eq!(pw, "test2");
                assert!(true);
            }
            PasswordCrackResult::Failure(_) => assert!(false),
        }
    }
}
