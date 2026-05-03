use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use zip_password_finder::gpu::GpuContext;
use zip_password_finder::gpu::pbkdf2::Pbkdf2Context;

const MAX_BATCH: u32 = 65_536;
const MAX_N_BLOCKS: u32 = 4; // AES-256 derived key = 4 SHA-1 output blocks

// Bigger batches were measured up to 524 288 and showed only ~10% headroom
// past 65 k for AES-256 (+7% for AES-128) before plateauing entirely.
// Not worth the run-time hit on a routine bench.

fn bench_pbkdf2_gpu(c: &mut Criterion) {
    let gpu = match GpuContext::init_blocking() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skipping GPU benches: {e}");
            return;
        }
    };
    eprintln!("GPU: {} ({})", gpu.adapter_name, gpu.backend);

    // Persistent context: pipeline, buffers, bind group built once.
    let pctx = Pbkdf2Context::new(&gpu, MAX_BATCH, MAX_N_BLOCKS).expect("Pbkdf2Context::new");

    let salt = [0u8; 16];
    let mut group = c.benchmark_group("pbkdf2_hmac_sha1_1000_gpu_aes256");
    group.sample_size(20);
    for batch in [256u32, 1024, 4096, 16384, 65536] {
        let owned: Vec<Vec<u8>> = (0..batch)
            .map(|i| format!("password_{i}").into_bytes())
            .collect();
        let pws: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

        group.throughput(Throughput::Elements(batch as u64));
        group.bench_function(format!("batch_{batch}"), |b| {
            b.iter(|| {
                let keys = pctx.derive(&pws, &salt, 1000, 66).unwrap();
                black_box(keys);
            });
        });
    }
    group.finish();

    let mut group = c.benchmark_group("pbkdf2_hmac_sha1_1000_gpu_aes128");
    group.sample_size(20);
    let salt = [0u8; 8];
    for batch in [4096u32, 16384, 65536] {
        let owned: Vec<Vec<u8>> = (0..batch)
            .map(|i| format!("password_{i}").into_bytes())
            .collect();
        let pws: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

        group.throughput(Throughput::Elements(batch as u64));
        group.bench_function(format!("batch_{batch}"), |b| {
            b.iter(|| {
                let keys = pctx.derive(&pws, &salt, 1000, 34).unwrap();
                black_box(keys);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_pbkdf2_gpu);
criterion_main!(benches);
