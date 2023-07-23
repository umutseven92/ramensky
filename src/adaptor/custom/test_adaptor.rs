//! TestAdaptor is a simple adaptor for testing and benchmarking purposes.

use std::error::Error;

use crate::adaptor::base::BaseAdaptor;
use crate::adaptor::safe_crack_result::SafeCrackResult;

pub struct TestAdaptor<'a> {
    password: &'a str,
}

impl<'a> TestAdaptor<'a> {
    pub fn new(password: &'a str) -> Self {
        TestAdaptor { password }
    }
}

impl<'a> BaseAdaptor for TestAdaptor<'a> {
    fn get_adaptor_name(&self) -> &str {
        "TestAdaptor"
    }

    fn try_password(&self, password: &String) -> Result<SafeCrackResult, Box<dyn Error>> {
        if password == self.password {
            Ok(SafeCrackResult::Success)
        } else {
            Ok(SafeCrackResult::Failure)
        }
    }
}
