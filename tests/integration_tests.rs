use ramensky::adaptor::custom::test_adaptor::TestAdaptor;
use ramensky::safe_cracker::options::Options;
use ramensky::safe_cracker::password_crack_result::PasswordCrackResult;
use ramensky::safe_cracker::safe_cracker::SafeCracker;

#[test]
fn should_find_in_common_passwords() {
    let safe_cracker = SafeCracker::build(Options::new(true, true, false, None)).unwrap();

    // qwerty is the 4th item in the common passwords list.
    let adaptor = TestAdaptor::new("qwerty");

    let result = safe_cracker.start(adaptor).unwrap();

    match result {
        PasswordCrackResult::Success(pw, _) => {
            assert_eq!(pw, "qwerty");
            assert!(true);
        }
        PasswordCrackResult::Failure(_) => assert!(false),
    }
}
