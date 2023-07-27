use std::error::Error;
use std::fs::read_to_string;

pub fn read_lines(filename: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let result: Vec<String> = read_to_string(filename)?
        .lines()
        .map(String::from)
        .collect();

    Ok(result)
}
