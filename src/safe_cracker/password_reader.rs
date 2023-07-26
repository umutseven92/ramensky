//! Module containing the iterator that reads from provided password lists.

use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Lines};

use crate::safe_cracker::reader_configuration::PwListConfiguration;

/// `PasswordReader` is an iterator that spits out a password everytime [`next()`](PasswordReader::next) is called.
/// These passwords are read from password files, provided in the [`build()`](PasswordReader::build) method.
pub struct PasswordReader {
    lines: Vec<Lines<BufReader<File>>>,
    limits: Vec<Option<usize>>,
    lines_index: usize,
    limit_acc: usize,
}

impl PasswordReader {
    /// Build a `PasswordReader` from the provided password file paths.
    /// Password files need to be newline separated lists of strings.
    pub fn build(pw_list_configs: Vec<PwListConfiguration>) -> Result<Self, Box<dyn Error>> {
        let mut lines = vec![];
        let mut limits = vec![];

        for config in pw_list_configs {
            let file = File::open(config.path)?;
            let reader = BufReader::new(file);
            lines.push(reader.lines());
            limits.push(config.amount);
        }

        Ok(Self {
            lines,
            lines_index: 0,
            limits,
            limit_acc: 0,
        })
    }
}

impl Iterator for PasswordReader {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.lines_index >= self.lines.len() {
            // We have exhausted all password sources.
            return None;
        }
        let current_limit = self.limits[self.lines_index];

        if current_limit.is_some() && self.limit_acc >= current_limit.unwrap() {
            // Move on to the next buffer.
            self.lines_index += 1;
            self.limit_acc = 0;
            return self.next();
        } else {
            let current_lines = &mut self.lines[self.lines_index];

            match current_lines.next() {
                None => {
                    // Move on to the next buffer.
                    self.lines_index += 1;
                    self.limit_acc = 0;
                    self.next()
                }
                Some(res) => {
                    self.limit_acc += 1;
                    Some(res.unwrap())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::safe_cracker::password_reader::PasswordReader;
    use crate::safe_cracker::reader_configuration::PwListConfiguration;

    #[test]
    fn can_read_multiple_pw_files() {
        let password_reader = PasswordReader::build(vec![
            PwListConfiguration::new("tests/resources/pw-list.txt", None),
            PwListConfiguration::new("tests/resources/pw-list.txt", None),
        ])
        .unwrap();

        let mut pws: Vec<String> = vec![];

        for pw in password_reader {
            pws.push(pw);
        }

        assert_eq!(pws, ["test1", "test2", "test3", "test1", "test2", "test3"]);
    }

    #[test]
    fn can_read_with_limits() {
        let password_reader = PasswordReader::build(vec![PwListConfiguration::new(
            "tests/resources/pw-list.txt",
            Some(2),
        )])
        .unwrap();

        let mut pws: Vec<String> = vec![];

        for pw in password_reader {
            pws.push(pw);
        }

        assert_eq!(pws, ["test1", "test2"]);
    }

    #[test]
    fn can_read_multiple_with_limits() {
        let password_reader = PasswordReader::build(vec![
            PwListConfiguration::new("tests/resources/pw-list.txt", Some(2)),
            PwListConfiguration::new("tests/resources/pw-list.txt", Some(1)),
        ])
        .unwrap();

        let mut pws: Vec<String> = vec![];

        for pw in password_reader {
            pws.push(pw);
        }

        // Take 2 from first list, 1 from second list.
        assert_eq!(pws, ["test1", "test2", "test1"]);
    }
}
