//! Module containing the password cracker.

use std::error::Error;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use crate::adaptor::attempt_result::AttemptResult;
use crate::adaptor::base::BaseAdaptor;
use crate::safe_cracker::brute_forcer::BruteForcer;
use crate::safe_cracker::helpers::read_lines;
use crate::safe_cracker::options::Options;
use crate::safe_cracker::password_crack_result::PasswordCrackResult;

const COMMON_PW_PATH: &str = "resources/common-passwords.txt";

pub struct SafeCracker<'a> {
    common_passwords: Option<Vec<String>>,
    custom_passwords: Option<Vec<String>>,
    brute_forcer: Option<BruteForcer>,
    options: Options<'a>,
}

#[macro_export]
macro_rules! print_with_ts {
    ($S:ident, $F:expr) => {
        if !$S.options.quiet {
            println!("{:?}\t{}", chrono::offset::Local::now(), $F);
        }
    };
}

impl<'a> SafeCracker<'a> {
    pub fn build(options: Options<'a>) -> Result<Self, Box<dyn Error>> {
        let mut common_passwords: Option<Vec<String>> = None;
        let mut custom_passwords: Option<Vec<String>> = None;
        let mut brute_forcer: Option<BruteForcer> = None;

        if options.try_common_passwords {
            if let Some(opt) = options.common_password_options {
                let mut common_passwords_uncut = read_lines(COMMON_PW_PATH)?;

                if let Some(amount) = opt.amount_to_use {
                    common_passwords_uncut = common_passwords_uncut[..=amount].to_vec();
                }

                common_passwords = Some(common_passwords_uncut);
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
            custom_passwords = Some(read_lines(custom_path)?);
        }

        if options.try_brute_forcing {
            if let Some(opt) = options.brute_forcing_options {
                brute_forcer = Some(BruteForcer::new(opt));
            } else {
                return Err("brute_forcing_options needs to set if try_brute_forcing is enabled.")?;
            }
        }

        Ok(Self {
            common_passwords,
            custom_passwords,
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
    /// match safe_cracker.start(&adaptor).unwrap() {
    ///     PasswordCrackResult::Success(pw, elapsed) => println!("Success! Password is {pw}. Execution took {} seconds", elapsed.as_secs()),
    ///     PasswordCrackResult::Failure(elapsed) => println!("Failure. Execution took {} seconds", elapsed.as_secs()),
    /// }
    /// ```
    pub fn start<T: BaseAdaptor + Sync>(
        &self,
        adaptor: &T,
    ) -> Result<PasswordCrackResult, Box<dyn Error>> {
        print_with_ts!(self, "Starting attempt.");

        let now = Instant::now();

        // Common passwords
        if let Some(success_result) = self.try_common_passwords(adaptor)? {
            return Ok(success_result);
        }

        // Custom passwords
        if let Some(success_result) = self.try_custom_password_list(adaptor)? {
            return Ok(success_result);
        }

        print_with_ts!(self, "Failure! Could not find the password.");
        print_with_ts!(
            self,
            format!("Total execution took {} seconds.", now.elapsed().as_secs())
        );
        Ok(PasswordCrackResult::Failure(now.elapsed()))
    }

    fn try_common_passwords<T: BaseAdaptor + Sync>(
        &self,
        adaptor: &T,
    ) -> Result<Option<PasswordCrackResult>, Box<dyn Error>> {
        if let Some(common_passwords) = &self.common_passwords {
            print_with_ts!(
                self,
                format!("Trying {} common passwords.", common_passwords.len())
            );
            Ok(self.try_passwords(adaptor, common_passwords)?)
        } else {
            Ok(None)
        }
    }

    fn try_custom_password_list<T: BaseAdaptor + Sync>(
        &self,
        adaptor: &T,
    ) -> Result<Option<PasswordCrackResult>, Box<dyn Error>> {
        if let Some(custom_password_list) = &self.custom_passwords {
            print_with_ts!(
                self,
                format!("Trying {} custom passwords.", custom_password_list.len())
            );

            Ok(self.try_passwords(adaptor, custom_password_list)?)
        } else {
            Ok(None)
        }
    }

    fn try_passwords<T: BaseAdaptor + Sync>(
        &self,
        adaptor: &T,
        password_list: &Vec<String>,
    ) -> Result<Option<PasswordCrackResult>, Box<dyn Error>> {
        let now = Instant::now();

        let result = self.try_password_list(adaptor, &password_list)?;

        match result {
            Some(pw) => {
                print_with_ts!(self, format!("Success! {pw} is the password."));
                print_with_ts!(
                    self,
                    format!("Execution took {} seconds.", now.elapsed().as_secs())
                );

                Ok(Some(PasswordCrackResult::Success(pw, now.elapsed())))
            }
            None => {
                print_with_ts!(
                    self,
                    "Failure! Could not find the password in custom passwords. Moving on.."
                );
                print_with_ts!(
                    self,
                    format!("Execution took {} seconds.", now.elapsed().as_secs())
                );

                Ok(None)
            }
        }
    }

    fn try_password_list<T: BaseAdaptor + Sync>(
        &self,
        adaptor: &T,
        password_list: &Vec<String>,
    ) -> Result<Option<String>, Box<dyn Error>> {
        let (tx, rx) = mpsc::channel();

        thread::scope(|scope| {
            scope.spawn(move || {
                for pw in password_list {
                    print_with_ts!(self, format!("Trying password {pw}"));

                    let result = adaptor.try_password(pw).unwrap();

                    match result {
                        AttemptResult::Success => {
                            tx.send(Some(String::from("test"))).unwrap();
                        }
                        AttemptResult::Failure => continue,
                    }
                }

                tx.send(Some(String::from("test"))).unwrap();
            });
        });

        let received = rx.recv().unwrap();

        // for pw in password_list {
        //     print_with_ts!(self, format!("Trying password {pw}"));
        //
        //     let result = adaptor.try_password(pw)?;
        //
        //     match result {
        //         AttemptResult::Success => {
        //             return Ok(Some(pw.clone()));
        //         }
        //         AttemptResult::Failure => continue,
        //     }
        // }

        Ok(None)
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

        let result = safe_cracker.start(&adaptor).unwrap();

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

        let result = safe_cracker.start(&adaptor).unwrap();

        match result {
            PasswordCrackResult::Success(pw, _) => {
                assert_eq!(pw, "test2");
                assert!(true);
            }
            PasswordCrackResult::Failure(_) => assert!(false),
        }
    }
}
