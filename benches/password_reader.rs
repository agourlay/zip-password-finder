use criterion::{Criterion, criterion_group, criterion_main};
use std::{hint::black_box, path::Path};
use zip_password_finder::password_reader::password_dictionary_reader_iter;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("read_passwords", |b| {
        let file_path = Path::new("test-files/generated-passwords-lowercase.txt");
        b.iter(|| {
            let iterator = password_dictionary_reader_iter(file_path.to_path_buf());
            let _last = black_box(iterator.last());
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
