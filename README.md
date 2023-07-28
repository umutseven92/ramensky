# Ramensky (WIP)

[Ramensky](https://en.wikipedia.org/wiki/Johnny_Ramensky) is a highly customisable password cracker backend, written in
Rust.

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
ramensky = { git = "https://github.com/umutseven92/ramensky.git" }
```

## Usage

### Creating an Adaptor

First, create an adaptor in your project, inheriting from [`BaseAdaptor`](src/adaptor/base.rs), fit for your purposes.

Example of a [custom adaptor](src/adaptor/custom/zip_adaptor.rs):

```rust
//! ZipAdaptor is an adaptor for decrypting password protected zip archives.
//! It uses `unzip` to try to unlock the file.
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
```

### Running the Safe Cracker

To use it with default options:

```rust
let safe_cracker = SafeCracker::build(Options::default()).unwrap();
let adaptor = TestAdaptor::without_delay("password123");

match safe_cracker.start(adaptor).unwrap() {
    PasswordCrackResult::Success(pw, elapsed) => println! ("Success! Password is {pw}. Execution took {} seconds", elapsed.as_secs()),
    PasswordCrackResult::Failure(elapsed) => println !("Failure. Execution took {} seconds", elapsed.as_secs()),
}
```

To see all available options, please see [`Options`](src/safe_cracker/options.rs).

## Execution Order

With default settings, Ramensky will:

1. Try the most common 1 million passwords (sourced from [here](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt)),
2. Try the passwords from the custom password list, if provided,
3. Try to brute force the password.

## ToDo

- [ ] Parallelization of execution
- [ ] Brute forcing step
- [ ] Save / load states