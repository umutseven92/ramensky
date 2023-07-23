use std::error::Error;

use crate::adaptor::safe_crack_result::SafeCrackResult;

pub trait BaseAdaptor {
    fn get_adaptor_name(&self) -> &str {
        "BaseAdaptor"
    }

    fn try_password(&self, password: &String) -> Result<SafeCrackResult, Box<dyn Error>>;
}
