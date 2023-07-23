use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

use ramensky::adaptor::custom::test_adaptor::TestAdaptor;
use ramensky::safe_cracker::options::Options;
use ramensky::safe_cracker::password_reader::PasswordReader;
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

    PasswordReader::build(vec![common_pw_path]).unwrap()
}

fn common_pw_list_reader_benchmark(c: &mut Criterion) {
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
    SafeCracker::build(Options::new(true, true, false, None, None)).unwrap()
}

fn common_pw_list_safe_cracker_benchmark(c: &mut Criterion) {
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
