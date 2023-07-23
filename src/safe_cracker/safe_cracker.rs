//! Module containing the password cracker.

use std::error::Error;
use std::time::Instant;

use crate::adaptor::attempt_result::AttemptResult;
use crate::adaptor::base::BaseAdaptor;
use crate::safe_cracker::options::Options;
use crate::safe_cracker::password_crack_result::PasswordCrackResult;
use crate::safe_cracker::password_reader::PasswordReader;

const COMMON_PW_PATH: &str = "resources/common-passwords.txt";

pub struct SafeCracker<'a> {
    password_reader: PasswordReader,
    options: Options<'a>,
}

impl<'a> SafeCracker<'a> {
    pub fn build(options: Options<'a>) -> Result<Self, Box<dyn Error>> {
        let mut paths = vec![];

        if options.try_common_passwords {
            paths.push(COMMON_PW_PATH);
        }

        if let Some(custom_path) = options.custom_pw_list_path {
            // TODO: Validate `custom_path`.
            paths.push(custom_path);
        }

        Ok(Self {
            password_reader: PasswordReader::build(paths)?,
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
    /// let adaptor = TestAdaptor::new("abcde");
    /// match safe_cracker.start(adaptor).unwrap() {
    ///     PasswordCrackResult::Success(pw, elapsed) => println!("Success! Password is {pw}. Execution took {} seconds", elapsed.as_secs()),
    ///     PasswordCrackResult::Failure(elapsed) => println!("Failure. Execution took {} seconds", elapsed.as_secs()),
    /// }
    /// ```
    pub fn start<T: BaseAdaptor>(self, adaptor: T) -> Result<PasswordCrackResult, Box<dyn Error>> {
        println!("Starting attempt..");
        let now = Instant::now();

        for pw in self.password_reader {
            if !self.options.quiet {
                println!("Trying password {pw}..");
            }

            let result = adaptor.try_password(&pw)?;

            match result {
                AttemptResult::Success => {
                    if !self.options.quiet {
                        println!("Success! {pw} is the password.");
                        println!("Execution took {} seconds.", now.elapsed().as_secs());
                    }

                    return Ok(PasswordCrackResult::Success(pw, now.elapsed()));
                }
                AttemptResult::Failure => continue,
            }
        }

        if !self.options.quiet {
            println!("Failure! Could not find the password.");
            println!("Execution took {} seconds.", now.elapsed().as_secs());
        }
        Ok(PasswordCrackResult::Failure(now.elapsed()))
    }
}

#[cfg(test)]
mod tests {
    use crate::adaptor::custom::test_adaptor::TestAdaptor;
    use crate::safe_cracker::options::Options;
    use crate::safe_cracker::password_crack_result::PasswordCrackResult;
    use crate::safe_cracker::safe_cracker::SafeCracker;

    #[test]
    fn should_find_in_common_passwords() {
        let safe_cracker = SafeCracker::build(Options::new(true, true, false, None)).unwrap();

        // "qwerty" is the 4th item in the common passwords list.
        let adaptor = TestAdaptor::new("qwerty");

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
    fn should_find_in_custom_list() {
        let custom_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/resources/pw-list.txt");
        let safe_cracker =
            SafeCracker::build(Options::new(true, false, false, Some(custom_path))).unwrap();

        // "test2" is contained in the custom password list.
        let adaptor = TestAdaptor::new("test2");

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
