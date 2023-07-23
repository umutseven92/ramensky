//! Module that contains the `BaseAdaptor`.

use std::error::Error;

use crate::adaptor::attempt_result::AttemptResult;

/// The base adaptor trait for all adaptors.
/// For an example of an adaptor, see [`ZipAdaptor`](crate::adaptor::custom::zip_adaptor::ZipAdaptor).
pub trait BaseAdaptor {
    /// This method will be called for every password that has been generated.
    /// If the result is ```SafeCrackResult::Success```, execution will end.
    /// If the result is ```SafeCrackResult::Failure```, execution will continue, until all passwords
    /// are exhausted.
    fn try_password(&self, password: &String) -> Result<AttemptResult, Box<dyn Error>>;
}
