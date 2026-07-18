use std::borrow::Cow;

use crate::gpu::GpuContext;

pub(crate) const HMAC_BLOCK_BYTES: usize = 64;
pub(crate) const SHA1_OUTPUT_BYTES: usize = 20;
pub(crate) const PASSWORD_WORDS: usize = HMAC_BLOCK_BYTES / 4;

// Must match `@workgroup_size(...)` in pbkdf2.wgsl.
const WORKGROUP_SIZE: u32 = 256;

#[derive(Debug)]
pub enum PbkdfError {
    PasswordTooLong { len: usize },
    SaltTooLong { len: usize },
    InvalidDerivedKeyLen(usize),
    Gpu(String),
}

impl std::fmt::Display for PbkdfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PasswordTooLong { len } => write!(
                f,
                "password length {len} exceeds {HMAC_BLOCK_BYTES}-byte HMAC block size (long-key path not implemented)"
            ),
            Self::SaltTooLong { len } => write!(
                f,
                "salt length {len} exceeds 51 bytes (would not fit with block index + padding)"
            ),
            Self::InvalidDerivedKeyLen(len) => {
                write!(f, "invalid derived key length {len}")
            }
            Self::Gpu(e) => write!(f, "GPU error: {e}"),
        }
    }
}

/// Pack one zero-padded 64-byte HMAC key block as 16 big-endian u32s.
pub(crate) fn pack_password(password: &[u8]) -> Result<[u32; PASSWORD_WORDS], PbkdfError> {
    if password.len() > HMAC_BLOCK_BYTES {
        return Err(PbkdfError::PasswordTooLong {
            len: password.len(),
        });
    }
    let mut padded = [0u8; HMAC_BLOCK_BYTES];
    padded[..password.len()].copy_from_slice(password);
    let mut out = [0u32; PASSWORD_WORDS];
    for (i, chunk) in padded.chunks_exact(4).enumerate() {
        out[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    Ok(out)
}

/// Pack `n_blocks` U_1 message blocks (one per output block index 1..=n_blocks).
/// Each block is `salt || i_be32 || 0x80 || zeros || ((64+salt_len+4)*8) as be64`,
/// padded to 64 bytes and packed as 16 big-endian u32s.
pub(crate) fn pack_u1_message_blocks(salt: &[u8], n_blocks: u32) -> Result<Vec<u32>, PbkdfError> {
    // We need salt_len + 4 (block index) + 1 (0x80 marker) + 8 (length) <= 64.
    if salt.len() > 51 {
        return Err(PbkdfError::SaltTooLong { len: salt.len() });
    }
    let bit_len = ((HMAC_BLOCK_BYTES + salt.len() + 4) * 8) as u64;
    let mut out = Vec::with_capacity((n_blocks as usize) * 16);
    for i in 1..=n_blocks {
        let mut block = [0u8; HMAC_BLOCK_BYTES];
        block[..salt.len()].copy_from_slice(salt);
        block[salt.len()..salt.len() + 4].copy_from_slice(&i.to_be_bytes());
        block[salt.len() + 4] = 0x80;
        block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        for chunk in block.chunks_exact(4) {
            out.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
    }
    Ok(out)
}

/// Persistent PBKDF2 worker — pre-allocates GPU buffers and compiles the
/// pipeline once, so per-batch cost is just one `queue.write_buffer` per input
/// + one dispatch + one readback. Use this from a worker thread.
pub struct Pbkdf2Context<'gpu> {
    gpu: &'gpu GpuContext,
    pipeline: wgpu::ComputePipeline,
    bind_group: wgpu::BindGroup,
    pwd_buf: wgpu::Buffer,
    u1_buf: wgpu::Buffer,
    dk_buf: wgpu::Buffer,
    params_buf: wgpu::Buffer,
    staging: wgpu::Buffer,
    max_batch: u32,
    max_n_blocks: u32,
}

impl<'gpu> Pbkdf2Context<'gpu> {
    /// Build a persistent PBKDF2 worker bound to `gpu`.
    ///
    /// Pre-allocates the password / U_1 / derived-key / params / staging
    /// buffers to fit any dispatch up to `max_batch` candidates with a
    /// derived-key length producing up to `max_n_blocks` SHA-1 output blocks
    /// (i.e. `derived_key_len <= max_n_blocks * 20` bytes), compiles the WGSL
    /// pipeline once, and builds the bind group. Subsequent calls to
    /// [`derive`](Self::derive) reuse all of it.
    ///
    /// `max_batch` and `max_n_blocks` are hard caps for any single call to
    /// [`derive`](Self::derive). Exceeding either returns
    /// [`PbkdfError::Gpu`].
    ///
    /// For WinZip-AES the relevant `max_n_blocks` values are 2 (AES-128, 34-
    /// byte derived key), 3 (AES-192, 50 bytes), or 4 (AES-256, 66 bytes).
    ///
    /// # Errors
    /// Returns [`PbkdfError::Gpu`] if `max_batch == 0` or `max_n_blocks == 0`.
    pub fn new(
        gpu: &'gpu GpuContext,
        max_batch: u32,
        max_n_blocks: u32,
    ) -> Result<Self, PbkdfError> {
        if max_batch == 0 {
            return Err(PbkdfError::Gpu("max_batch must be > 0".into()));
        }
        if max_n_blocks == 0 {
            return Err(PbkdfError::Gpu("max_n_blocks must be > 0".into()));
        }

        let device = &gpu.device;

        let pwd_bytes = (max_batch as u64) * (HMAC_BLOCK_BYTES as u64);
        let u1_bytes = (max_n_blocks as u64) * (HMAC_BLOCK_BYTES as u64);
        let dk_bytes = (max_batch as u64) * (max_n_blocks as u64) * (SHA1_OUTPUT_BYTES as u64);

        let pwd_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("pbkdf2-passwords"),
            size: pwd_bytes,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let u1_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("pbkdf2-u1-blocks"),
            size: u1_bytes,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let dk_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("pbkdf2-derived-keys"),
            size: dk_bytes,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let params_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("pbkdf2-params"),
            size: 16,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let staging = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("pbkdf2-staging"),
            size: dk_bytes,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("pbkdf2-shader"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(include_str!("pbkdf2.wgsl"))),
        });
        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("pbkdf2-pipeline"),
            layout: None,
            module: &shader,
            entry_point: Some("main"),
            compilation_options: Default::default(),
            cache: None,
        });

        let bgl = pipeline.get_bind_group_layout(0);
        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("pbkdf2-bind-group"),
            layout: &bgl,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: pwd_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: u1_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: dk_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: params_buf.as_entire_binding(),
                },
            ],
        });

        Ok(Self {
            gpu,
            pipeline,
            bind_group,
            pwd_buf,
            u1_buf,
            dk_buf,
            params_buf,
            staging,
            max_batch,
            max_n_blocks,
        })
    }

    /// Derive PBKDF2-HMAC-SHA1 keys for `passwords` in a single GPU dispatch.
    ///
    /// All passwords share `salt`, `iterations`, and `derived_key_len`.
    /// WinZip-AES fixes `iterations` to 1000.
    ///
    /// Returns one `Vec<u8>` per input password, each of length
    /// `derived_key_len`. The output `Vec` is in the same order as the input
    /// slice, so `output[i]` is the derived key for `passwords[i]`.
    ///
    /// Blocks the calling thread until the GPU dispatch completes and the
    /// output is mapped back to host memory.
    ///
    /// # Errors
    /// - [`PbkdfError::PasswordTooLong`] if any password exceeds 64 bytes
    ///   (HMAC long-key path is not implemented).
    /// - [`PbkdfError::SaltTooLong`] if `salt` exceeds 51 bytes (would not fit
    ///   in a single SHA-1 block alongside the block index and padding).
    /// - [`PbkdfError::InvalidDerivedKeyLen`] if `derived_key_len == 0`.
    /// - [`PbkdfError::Gpu`] if the batch size or required block count
    ///   exceeds the bounds set in [`new`](Self::new), or if a wgpu buffer
    ///   mapping fails.
    pub fn derive(
        &self,
        passwords: &[&[u8]],
        salt: &[u8],
        iterations: u32,
        derived_key_len: usize,
    ) -> Result<Vec<Vec<u8>>, PbkdfError> {
        if derived_key_len == 0 {
            return Err(PbkdfError::InvalidDerivedKeyLen(0));
        }
        let n_blocks = derived_key_len.div_ceil(SHA1_OUTPUT_BYTES) as u32;
        let n_passwords = passwords.len() as u32;
        if n_passwords == 0 {
            return Ok(Vec::new());
        }
        if n_passwords > self.max_batch {
            return Err(PbkdfError::Gpu(format!(
                "batch size {n_passwords} exceeds context max_batch {}",
                self.max_batch
            )));
        }
        if n_blocks > self.max_n_blocks {
            return Err(PbkdfError::Gpu(format!(
                "derived_key_len needs {n_blocks} output blocks, exceeds context max_n_blocks {}",
                self.max_n_blocks
            )));
        }

        // Pack inputs and stream them into the persistent buffers.
        let mut packed_passwords = Vec::with_capacity(passwords.len() * PASSWORD_WORDS);
        for pw in passwords {
            let p = pack_password(pw)?;
            packed_passwords.extend_from_slice(&p);
        }
        let u1_blocks = pack_u1_message_blocks(salt, n_blocks)?;
        let params = [n_passwords, n_blocks, iterations, 0u32];

        self.gpu
            .queue
            .write_buffer(&self.pwd_buf, 0, bytemuck::cast_slice(&packed_passwords));
        self.gpu
            .queue
            .write_buffer(&self.u1_buf, 0, bytemuck::cast_slice(&u1_blocks));
        self.gpu
            .queue
            .write_buffer(&self.params_buf, 0, bytemuck::cast_slice(&params));

        let dk_words_per_password = (n_blocks as usize) * 5;
        let dk_used_bytes = (passwords.len() * dk_words_per_password * 4) as u64;

        let mut encoder = self
            .gpu
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("pbkdf2-encoder"),
            });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("pbkdf2-pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &self.bind_group, &[]);
            let workgroups = (n_passwords as usize).div_ceil(WORKGROUP_SIZE as usize) as u32;
            pass.dispatch_workgroups(workgroups, 1, 1);
        }
        encoder.copy_buffer_to_buffer(&self.dk_buf, 0, &self.staging, 0, dk_used_bytes);
        self.gpu.queue.submit(Some(encoder.finish()));

        // Read back.
        let slice = self.staging.slice(..dk_used_bytes);
        let (sender, receiver) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |r| {
            let _ = sender.send(r);
        });
        self.gpu
            .device
            .poll(wgpu::PollType::wait_indefinitely())
            .map_err(|e| PbkdfError::Gpu(format!("poll failed: {e:?}")))?;
        receiver
            .recv()
            .map_err(|e| PbkdfError::Gpu(format!("map_async channel closed: {e}")))?
            .map_err(|e| PbkdfError::Gpu(format!("buffer map failed: {e}")))?;

        let mapped = slice.get_mapped_range();
        let dk_words: &[u32] = bytemuck::cast_slice(&mapped);

        let mut out: Vec<Vec<u8>> = Vec::with_capacity(passwords.len());
        let block_bytes = (n_blocks as usize) * SHA1_OUTPUT_BYTES;
        for pid in 0..passwords.len() {
            let mut full = Vec::with_capacity(block_bytes);
            let off = pid * dk_words_per_password;
            for w in 0..dk_words_per_password {
                full.extend_from_slice(&dk_words[off + w].to_be_bytes());
            }
            full.truncate(derived_key_len);
            out.push(full);
        }
        drop(mapped);
        self.staging.unmap();

        Ok(out)
    }
}

/// One-shot wrapper: builds a fresh `Pbkdf2Context` sized for this exact call.
/// Test-only — production code paths reuse `Pbkdf2Context` directly.
#[cfg(test)]
fn pbkdf2_hmac_sha1_gpu(
    ctx: &GpuContext,
    passwords: &[&[u8]],
    salt: &[u8],
    iterations: u32,
    derived_key_len: usize,
) -> Result<Vec<Vec<u8>>, PbkdfError> {
    if passwords.is_empty() {
        return Ok(Vec::new());
    }
    let n_blocks = derived_key_len.div_ceil(SHA1_OUTPUT_BYTES).max(1) as u32;
    let pctx = Pbkdf2Context::new(ctx, passwords.len() as u32, n_blocks)?;
    pctx.derive(passwords, salt, iterations, derived_key_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::Hmac;
    use sha1::Sha1;

    fn cpu(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; dk_len];
        pbkdf2::pbkdf2::<Hmac<Sha1>>(password, salt, iterations, &mut out).unwrap();
        out
    }

    fn check_one(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) {
        let ctx = GpuContext::init_blocking().expect("GPU init");
        let pws: &[&[u8]] = &[password];
        let gpu = pbkdf2_hmac_sha1_gpu(&ctx, pws, salt, iterations, dk_len).expect("gpu pbkdf2");
        let ref_key = cpu(password, salt, iterations, dk_len);
        assert_eq!(
            gpu[0],
            ref_key,
            "mismatch for pw={password:?} salt_len={} iter={iterations} dk_len={dk_len}\n  gpu = {:02x?}\n  cpu = {:02x?}",
            salt.len(),
            gpu[0],
            ref_key
        );
    }

    #[test]
    fn pbkdf2_short_password_aes128() {
        // AES-128: derived_key_length = 2*16 + 2 = 34 bytes, salt = 8 bytes.
        check_one(b"password", &[1u8; 8], 1000, 34);
    }

    #[test]
    fn pbkdf2_short_password_aes192() {
        // AES-192: derived_key_length = 2*24 + 2 = 50 bytes, salt = 12 bytes.
        check_one(b"password", &[2u8; 12], 1000, 50);
    }

    #[test]
    fn pbkdf2_short_password_aes256() {
        // AES-256: derived_key_length = 2*32 + 2 = 66 bytes, salt = 16 bytes.
        check_one(b"password", &[3u8; 16], 1000, 66);
    }

    #[test]
    fn pbkdf2_empty_password() {
        check_one(b"", &[7u8; 16], 1000, 66);
    }

    #[test]
    fn pbkdf2_one_iteration() {
        check_one(b"hello", &[0xAA; 16], 1, 66);
    }

    #[test]
    fn pbkdf2_low_iteration_count() {
        check_one(b"hello", &[0xAA; 16], 100, 66);
    }

    #[test]
    fn pbkdf2_password_exactly_64_bytes() {
        let pw = [b'x'; 64];
        check_one(&pw, &[0x55; 16], 1000, 66);
    }

    #[test]
    fn pbkdf2_varied_salt_lengths() {
        for salt_len in [1, 4, 7, 8, 11, 12, 15, 16, 20, 32, 51] {
            let salt: Vec<u8> = (0..salt_len as u8).collect();
            check_one(b"password", &salt, 1000, 66);
        }
    }

    #[test]
    fn pbkdf2_batched_passwords() {
        let ctx = GpuContext::init_blocking().expect("GPU init");
        let salt = [0x42u8; 16];
        let owned: Vec<Vec<u8>> = (0..256u32)
            .map(|i| format!("password_{i}").into_bytes())
            .collect();
        let pws: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        let gpu = pbkdf2_hmac_sha1_gpu(&ctx, &pws, &salt, 1000, 66).expect("gpu pbkdf2");
        for (i, pw) in owned.iter().enumerate() {
            let ref_key = cpu(pw, &salt, 1000, 66);
            assert_eq!(gpu[i], ref_key, "mismatch at index {i} for password {pw:?}");
        }
    }

    #[test]
    fn pbkdf2_batched_partially_filling_workgroup() {
        // Sizes that don't align to the kernel's workgroup_size.
        for n in [1, 2, 7, 63, 64, 65, 100, 257] {
            let ctx = GpuContext::init_blocking().expect("GPU init");
            let salt = [0xAA; 16];
            let owned: Vec<Vec<u8>> = (0..n).map(|i| format!("p_{i}").into_bytes()).collect();
            let pws: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
            let gpu = pbkdf2_hmac_sha1_gpu(&ctx, &pws, &salt, 1000, 66).expect("gpu pbkdf2");
            assert_eq!(gpu.len(), n);
            for (i, pw) in owned.iter().enumerate() {
                let ref_key = cpu(pw, &salt, 1000, 66);
                assert_eq!(gpu[i], ref_key, "mismatch at n={n} index {i}");
            }
        }
    }
}
