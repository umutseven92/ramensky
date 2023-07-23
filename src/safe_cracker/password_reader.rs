//! Module containing the iterator that reads from provided password lists.

use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Lines};

/// `PasswordReader` is an iterator that spits out a password everytime [`next()`](PasswordReader::next) is called.
/// These passwords are read from password files, provided in the [`build()`](PasswordReader::build) method.
pub struct PasswordReader {
    lines: Vec<Lines<BufReader<File>>>,
    lines_index: usize,
}

impl PasswordReader {
    /// Build a `PasswordReader` from the provided password file paths.
    /// Password files need to be newline separated lists of strings.
    pub fn build(source_paths: Vec<&str>) -> Result<Self, Box<dyn Error>> {
        let mut lines = vec![];

        for path in source_paths {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            lines.push(reader.lines());
        }

        Ok(Self {
            lines,
            lines_index: 0,
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
        let current_lines = &mut self.lines[self.lines_index];

        match current_lines.next() {
            None => {
                // Move on to the next buffer.
                self.lines_index += 1;
                self.next()
            }
            Some(res) => Some(res.unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::safe_cracker::password_reader::PasswordReader;

    #[test]
    fn can_read_multiple_pw_files() {
        let password_reader = PasswordReader::build(vec![
            "tests/resources/pw-list.txt",
            "tests/resources/pw-list.txt",
        ])
        .unwrap();

        let mut pws: Vec<String> = vec![];

        for pw in password_reader {
            pws.push(pw);
        }

        assert_eq!(pws, ["test1", "test2", "test3", "test1", "test2", "test3"]);
    }
}
