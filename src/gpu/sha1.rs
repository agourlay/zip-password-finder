// Single-block SHA-1 driver kernel — exists only to validate the WGSL
// `sha1_compress` against the RustCrypto reference. Production code path is
// in `pbkdf2.rs`; this file is test-only.

#![cfg(test)]

use std::borrow::Cow;

use crate::gpu::GpuContext;

fn pad_message(message: &[u8]) -> Vec<u32> {
    let bit_len = (message.len() as u64) * 8;
    let mut padded = message.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    debug_assert_eq!(padded.len() % 64, 0);

    padded
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn sha1_gpu(ctx: &GpuContext, message: &[u8]) -> Result<[u8; 20], String> {
    pollster::block_on(sha1_gpu_async(ctx, message))
}

async fn sha1_gpu_async(ctx: &GpuContext, message: &[u8]) -> Result<[u8; 20], String> {
    use wgpu::util::DeviceExt;

    let blocks_words = pad_message(message);
    let n_blocks = (blocks_words.len() / 16) as u32;
    let blocks_bytes: &[u8] = bytemuck::cast_slice(&blocks_words);

    let blocks_buffer = ctx
        .device
        .create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("sha1-blocks"),
            contents: blocks_bytes,
            usage: wgpu::BufferUsages::STORAGE,
        });

    let state_buffer = ctx.device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("sha1-state"),
        size: 5 * 4,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        mapped_at_creation: false,
    });

    let params = [n_blocks, 0u32, 0u32, 0u32];
    let params_buffer = ctx
        .device
        .create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("sha1-params"),
            contents: bytemuck::cast_slice(&params),
            usage: wgpu::BufferUsages::UNIFORM,
        });

    let staging = ctx.device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("sha1-staging"),
        size: 5 * 4,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let shader = ctx
        .device
        .create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("sha1-shader"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(include_str!("sha1.wgsl"))),
        });

    let pipeline = ctx
        .device
        .create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("sha1-pipeline"),
            layout: None,
            module: &shader,
            entry_point: Some("main"),
            compilation_options: Default::default(),
            cache: None,
        });

    let bgl = pipeline.get_bind_group_layout(0);
    let bind_group = ctx.device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("sha1-bind-group"),
        layout: &bgl,
        entries: &[
            wgpu::BindGroupEntry {
                binding: 0,
                resource: blocks_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 1,
                resource: state_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 2,
                resource: params_buffer.as_entire_binding(),
            },
        ],
    });

    let mut encoder = ctx
        .device
        .create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("sha1-encoder"),
        });
    {
        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("sha1-pass"),
            timestamp_writes: None,
        });
        pass.set_pipeline(&pipeline);
        pass.set_bind_group(0, &bind_group, &[]);
        pass.dispatch_workgroups(1, 1, 1);
    }
    encoder.copy_buffer_to_buffer(&state_buffer, 0, &staging, 0, 5 * 4);
    ctx.queue.submit(Some(encoder.finish()));

    let slice = staging.slice(..);
    let (sender, receiver) = std::sync::mpsc::channel();
    slice.map_async(wgpu::MapMode::Read, move |r| {
        let _ = sender.send(r);
    });
    ctx.device
        .poll(wgpu::PollType::wait_indefinitely())
        .expect("poll");
    receiver
        .recv()
        .map_err(|e| format!("map_async channel closed: {e}"))?
        .map_err(|e| format!("buffer map failed: {e}"))?;

    let mapped = slice.get_mapped_range();
    let state: &[u32] = bytemuck::cast_slice(&mapped);
    let mut digest = [0u8; 20];
    for (i, w) in state.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    drop(mapped);
    staging.unmap();

    Ok(digest)
}

mod tests {
    use super::*;
    use sha1::{Digest, Sha1};

    fn cpu_digest(msg: &[u8]) -> [u8; 20] {
        let out = Sha1::digest(msg);
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&out);
        arr
    }

    fn check(msg: &[u8]) {
        let ctx = GpuContext::init_blocking().expect("GPU init");
        let gpu = sha1_gpu(&ctx, msg).expect("sha1_gpu");
        let cpu = cpu_digest(msg);
        assert_eq!(
            gpu,
            cpu,
            "mismatch for message of length {}: gpu={:02x?} cpu={:02x?}",
            msg.len(),
            gpu,
            cpu
        );
    }

    #[test]
    fn sha1_empty() {
        check(b"");
    }

    #[test]
    fn sha1_abc() {
        check(b"abc");
    }

    #[test]
    fn sha1_two_blocks() {
        // FIPS 180 multi-block test vector — exactly 56 bytes, padding spills
        // into a second block.
        check(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    }

    #[test]
    fn sha1_exactly_one_block() {
        // 55 bytes — last message that still fits with padding in a single block.
        check(&[b'a'; 55]);
    }

    #[test]
    fn sha1_64_bytes() {
        // Exactly one block of message — padding forces a second block.
        check(&[b'a'; 64]);
    }

    #[test]
    fn sha1_long_random_lengths() {
        // Sweep awkward sizes around block boundaries.
        for len in [1, 3, 55, 56, 63, 64, 65, 119, 120, 127, 128, 200, 1000] {
            let msg: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
            let ctx = GpuContext::init_blocking().expect("GPU init");
            let gpu = sha1_gpu(&ctx, &msg).expect("sha1_gpu");
            let cpu = cpu_digest(&msg);
            assert_eq!(
                gpu, cpu,
                "mismatch at len {len}: gpu={gpu:02x?} cpu={cpu:02x?}"
            );
        }
    }
}
