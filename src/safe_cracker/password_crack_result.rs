use std::time::Duration;

/// Result of the execution of the `SafeCracker`.
pub enum PasswordCrackResult {
    /// Password was found successfully. Contains the password, and the duration of the execution.
    Success(String, Duration),

    /// Password was not found. Contains the duration of the execution.
    Failure(Duration),
}
