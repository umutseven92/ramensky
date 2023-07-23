//! ZipAdaptor is an adaptor for decrypting password protected zip archives.
//! It uses `unzip` to try to unlock the file.

use std::error::Error;
use std::process::Command;
use std::str;

use crate::adaptor::attempt_result::AttemptResult;
use crate::adaptor::base::BaseAdaptor;

pub struct ZipAdaptor<'a> {
    /// Path to the zip file that is encrpyted.
    zip_path: &'a str,

    /// Where to extract the file, if the password is found. Needs to be a directory.
    /// If it doesn't exist, it will be created.
    extract_path: &'a str,
}

impl<'a> ZipAdaptor<'a> {
    pub fn new(zip_path: &'a str, extract_path: &'a str) -> Self {
        Self {
            zip_path,
            extract_path,
        }
    }
}

impl<'a> BaseAdaptor for ZipAdaptor<'a> {
    fn try_password(&self, password: &String) -> Result<AttemptResult, Box<dyn Error>> {
        let command = format!(
            "unzip -P {password} {} -d {}",
            self.zip_path, self.extract_path
        );

        let output = if cfg!(target_os = "windows") {
            Command::new("cmd")
                .args(["/C", command.as_str()])
                .output()
                .expect(format!("Failed to execute command {}", command.as_str()).as_str())
        } else {
            Command::new("sh")
                .arg("-c")
                .arg(command.as_str())
                .output()
                .expect(format!("Failed to execute command {}", command.as_str()).as_str())
        };

        if output.status.success() {
            Ok(AttemptResult::Success)
        } else {
            Ok(AttemptResult::Failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::adaptor::attempt_result::AttemptResult;
    use crate::adaptor::base::BaseAdaptor;
    use crate::adaptor::custom::zip_adaptor::ZipAdaptor;

    #[test]
    fn can_unzip() {
        let zip_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/resources/test.zip");
        let extract_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/out/");

        let zip_adaptor = ZipAdaptor::new(zip_path, extract_path);

        // The password for the test.zip file is "test".
        let pw = String::from("test");

        matches!(
            zip_adaptor.try_password(&pw).unwrap(),
            AttemptResult::Success
        );

        // Remove the extracted test file.
        fs::remove_file(extract_path.to_owned() + "test").unwrap();
    }
}
