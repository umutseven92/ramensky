use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

use ramensky::adaptor::custom::test_adaptor::TestAdaptor;
use ramensky::safe_cracker::common_pw_list_options::CommonPwListOptions;
use ramensky::safe_cracker::options::Options;
use ramensky::safe_cracker::safe_cracker::SafeCracker;

fn crack_password(safe_cracker: SafeCracker) {
    let adaptor = TestAdaptor::new("not-in-common-list", Duration::from_micros(1));

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
    // Benchmark for how fast SafeCracker goes through 100_000 passwords.
    c.bench_function("Safe Cracker | Common PW list, 1 μs delay", |b| {
        b.iter_batched(
            || create_safe_cracker(),
            |safe_cracker| crack_password(safe_cracker),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, common_pw_list_safe_cracker_benchmark);
criterion_main!(benches);
