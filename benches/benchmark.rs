use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

use ramensky::safe_cracker::password_reader::PasswordReader;

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

fn common_pw_list_benchmark(c: &mut Criterion) {
    c.bench_function("Password Reader | Common PW list", |b| {
        b.iter_batched(
            || create_reader(),
            |reader| read_pw_list(reader),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, common_pw_list_benchmark);
criterion_main!(benches);
