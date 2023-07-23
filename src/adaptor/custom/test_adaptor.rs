//! TestAdaptor is a simple adaptor for testing and benchmarking purposes. It mocks how a normal Adaptor might work.
//! It sleeps for a certain amount, checks whether the guessed password is correct, and returns the result.

use std::error::Error;
use std::thread;
use std::time::Duration;

use crate::adaptor::attempt_result::AttemptResult;
use crate::adaptor::base::BaseAdaptor;

pub struct TestAdaptor<'a> {
    password: &'a str,
    delay: Duration,
}

impl<'a> TestAdaptor<'a> {
    pub fn without_delay(password: &'a str) -> Self {
        TestAdaptor::new(password, Duration::from_millis(0))
    }

    pub fn new(password: &'a str, delay: Duration) -> Self {
        TestAdaptor { password, delay }
    }
}

impl<'a> BaseAdaptor for TestAdaptor<'a> {
    fn try_password(&self, password: &String) -> Result<AttemptResult, Box<dyn Error>> {
        thread::sleep(self.delay);

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
        let adaptor = TestAdaptor::without_delay("abcde");

        matches!(
            adaptor.try_password(&String::from("abcde")).unwrap(),
            AttemptResult::Success
        );
    }
}
