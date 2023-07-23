use std::error::Error;
use std::time::Instant;

use crate::adaptor::base::BaseAdaptor;
use crate::adaptor::safe_crack_result::SafeCrackResult;
use crate::safe_cracker::options::Options;
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

    pub fn start<T: BaseAdaptor>(self, adaptor: T) -> Result<SafeCrackResult, Box<dyn Error>> {
        println!("Starting attempt..");
        let now = Instant::now();

        for pw in self.password_reader {
            if !self.options.quiet {
                println!("Trying password {pw}..");
            }

            let result = adaptor.try_password(&pw)?;

            match result {
                SafeCrackResult::Success => {
                    println!("Success! {pw} is the password.");
                    println!("Execution took {} seconds.", now.elapsed().as_secs());

                    return Ok(SafeCrackResult::Success);
                }
                SafeCrackResult::Failure => continue,
            }
        }

        println!("Failure! Could not find the password.");
        println!("Execution took {} seconds.", now.elapsed().as_secs());
        Ok(SafeCrackResult::Failure)
    }
}
