//! Module containing the password cracker.

use std::error::Error;
use std::time::Instant;

use crate::adaptor::attempt_result::AttemptResult;
use crate::adaptor::base::BaseAdaptor;
use crate::safe_cracker::options::Options;
use crate::safe_cracker::password_crack_result::PasswordCrackResult;
use crate::safe_cracker::password_reader::PasswordReader;

pub struct SafeCracker<'a> {
    password_reader: PasswordReader,
    options: Options<'a>,
}

impl<'a> SafeCracker<'a> {
    pub fn build(options: Options<'a>) -> Result<Self, Box<dyn Error>> {
        let filepath = "resources/common-passwords.txt";
        Ok(Self {
            password_reader: PasswordReader::build(vec![filepath])?,
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
