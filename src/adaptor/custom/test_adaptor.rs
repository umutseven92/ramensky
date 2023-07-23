//! TestAdaptor is a simple adaptor for testing and benchmarking purposes.
//! If simply checks whether the guessed password if the initial provided password.

use std::error::Error;

use crate::adaptor::attempt_result::AttemptResult;
use crate::adaptor::base::BaseAdaptor;

pub struct TestAdaptor<'a> {
    password: &'a str,
}

impl<'a> TestAdaptor<'a> {
    pub fn new(password: &'a str) -> Self {
        TestAdaptor { password }
    }
}

impl<'a> BaseAdaptor for TestAdaptor<'a> {
    fn try_password(&self, password: &String) -> Result<AttemptResult, Box<dyn Error>> {
        if password == self.password {
            Ok(AttemptResult::Success)
        } else {
            Ok(AttemptResult::Failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::adaptor::attempt_result::AttemptResult;
    use crate::adaptor::custom::test_adaptor::TestAdaptor;

    use super::*;

    #[test]
    fn can_decrypt() {
        let adaptor = TestAdaptor::new("abcde");

        matches!(
            adaptor.try_password(&String::from("abcde")).unwrap(),
            AttemptResult::Success
        );
    }
}
