//! ZipAdaptor is an adaptor for decrypting password protected zip archives.
//! It uses `unzip` to try to unlock the file.

use std::error::Error;
use std::process::Command;
use std::str;

use crate::adaptor::base::BaseAdaptor;
use crate::adaptor::safe_crack_result::SafeCrackResult;

pub struct ZipAdaptor<'a> {
    zip_path: &'a str,
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
    fn get_adaptor_name(&self) -> &str {
        "ZipAdaptor"
    }

    fn try_password(&self, password: &String) -> Result<SafeCrackResult, Box<dyn Error>> {
        let command = format!(
            "unzip -P {password} {} -d {}",
            self.zip_path, self.extract_path
        );

        let output = if cfg!(target_os = "windows") {
            Command::new("cmd")
                .args(["/C", command.as_str()])
                .output()
                .expect("failed to execute process")
        } else {
            Command::new("sh")
                .arg("-c")
                .arg(command.as_str())
                .output()
                .expect("failed to execute process")
        };

        if output.status.success() {
            Ok(SafeCrackResult::Success)
        } else {
            Ok(SafeCrackResult::Failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::adaptor::base::BaseAdaptor;
    use crate::adaptor::custom::zip_adaptor::ZipAdaptor;
    use crate::adaptor::safe_crack_result::SafeCrackResult;

    #[test]
    fn can_unzip() {
        let zip_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/resources/test.zip");
        let extract_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/out/");

        let zip_adaptor = ZipAdaptor::new(zip_path, extract_path);

        // The password for the test.zip file is test.
        let pw = String::from("test");

        match zip_adaptor.try_password(&pw).unwrap() {
            SafeCrackResult::Success => assert!(true),
            SafeCrackResult::Failure => assert!(false),
        }

        // Remove the extracted test file.
        fs::remove_file(extract_path.to_owned() + "test").unwrap();
    }
}
