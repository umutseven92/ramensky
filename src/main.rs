use ramensky::adaptor::custom::test_adaptor::TestAdaptor;
use ramensky::adaptor::safe_crack_result::SafeCrackResult;
use ramensky::safe_cracker::options::Options;
use ramensky::safe_cracker::safe_cracker::SafeCracker;

fn main() {
    let safe_cracker = SafeCracker::build(Options::default()).unwrap();

    let adaptor = TestAdaptor::new("abcde");

    match safe_cracker.start(adaptor).unwrap() {
        SafeCrackResult::Success => println!("Success!"),
        SafeCrackResult::Failure => println!("Failure!"),
    }
}
