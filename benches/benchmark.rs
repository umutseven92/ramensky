use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

use ramensky::adaptor::custom::test_adaptor::TestAdaptor;
use ramensky::safe_cracker::common_pw_list_options::CommonPwListOptions;
use ramensky::safe_cracker::options::Options;
use ramensky::safe_cracker::password_reader::PasswordReader;
use ramensky::safe_cracker::reader_configuration::PwListConfiguration;
use ramensky::safe_cracker::safe_cracker::SafeCracker;

fn read_pw_list(reader: PasswordReader) {
    for pw in reader {
        black_box(pw);
    }
}

fn create_reader() -> PasswordReader {
    let common_pw_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/resources/common-passwords.txt"
    );

    PasswordReader::build(vec![PwListConfiguration::new(common_pw_path, None)]).unwrap()
}

fn common_pw_list_reader_benchmark(c: &mut Criterion) {
    // Benchmark for how fast PasswordReader reads every password from the common passwords list.
    // This only benchmarks the actual reading, it does not benchmark and kind of password attempt.
    c.bench_function("Password Reader | Common PW list", |b| {
        b.iter_batched(
            || create_reader(),
            |reader| read_pw_list(reader),
            BatchSize::SmallInput,
        );
    });
}

fn crack_password(safe_cracker: SafeCracker) {
    // "vjht008" is the last password in the common passwords list.
    let adaptor = TestAdaptor::new("vjht008", Duration::from_micros(1));

    let result = safe_cracker.start(adaptor).unwrap();

    black_box(result);
}

fn create_safe_cracker() -> SafeCracker<'static> {
    SafeCracker::build(Options::new(
        true,
        true,
        Some(CommonPwListOptions::build(Some(100_000)).unwrap()),
        false,
        None,
        None,
    ))
    .unwrap()
}

fn common_pw_list_safe_cracker_benchmark(c: &mut Criterion) {
    // Benchmark for how fast SafeCracker goes through 1M passwords.
    c.bench_function("Safe Cracker | Common PW list, 1 μs delay", |b| {
        b.iter_batched(
            || create_safe_cracker(),
            |safe_cracker| crack_password(safe_cracker),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    common_pw_list_reader_benchmark,
    common_pw_list_safe_cracker_benchmark
);
criterion_main!(benches);
