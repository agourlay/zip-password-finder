use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use hmac::Hmac;
use sha1::Sha1;
use std::hint::black_box;

fn bench_pbkdf2(c: &mut Criterion) {
    let salt = [0u8; 16];
    let password = b"password123";

    let mut group = c.benchmark_group("pbkdf2_hmac_sha1_1000");
    group.throughput(Throughput::Elements(1));

    // AES-128 — derived key 34 bytes (2 SHA-1 output blocks)
    group.bench_function("aes128_one_password", |b| {
        let mut out = [0u8; 34];
        b.iter(|| {
            pbkdf2::pbkdf2::<Hmac<Sha1>>(black_box(password), &salt, 1000, &mut out).unwrap();
        });
    });

    // AES-256 — derived key 66 bytes (4 SHA-1 output blocks)
    group.bench_function("aes256_one_password", |b| {
        let mut out = [0u8; 66];
        b.iter(|| {
            pbkdf2::pbkdf2::<Hmac<Sha1>>(black_box(password), &salt, 1000, &mut out).unwrap();
        });
    });

    group.finish();
}

criterion_group!(benches, bench_pbkdf2);
criterion_main!(benches);
