use criterion::{black_box, criterion_group, criterion_main, Criterion};
use indicatif::ProgressBar;
use zip_password_finder::charsets::charset_lowercase_letters;
use zip_password_finder::password_gen::password_generator_iter;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("generate_password", |b| {
        let charset = charset_lowercase_letters();
        let min_password_len = 3;
        let max_password_len = 5;
        b.iter(|| {
            let pb = ProgressBar::hidden();
            let iterator =
                password_generator_iter(&charset, min_password_len, max_password_len, pb);
            let _last = black_box(iterator.last());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
