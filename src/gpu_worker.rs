use crate::gpu::GpuContext;
use crate::gpu::pbkdf2::{Pbkdf2Context, SHA1_OUTPUT_BYTES};
use crate::password_finder::Strategy;
use crate::password_gen::password_generator_iter;
use crate::password_mask::mask_password_iter;
use crate::password_reader::password_dictionary_reader_iter;
use crate::zip_utils::AesInfo;
use indicatif::ProgressBar;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::thread;
use std::thread::JoinHandle;
use zip::ZipArchive;
use zip::result::ZipError;

// PBKDF2 iteration count fixed by the WinZip-AES spec (APPNOTE 7.2 § 7.2).
const WINZIP_AES_PBKDF2_ITERATIONS: u32 = 1000;

fn iterator_for_strategy(
    strategy: Strategy,
    progress_bar: ProgressBar,
) -> Box<dyn Iterator<Item = Vec<u8>> + Send> {
    match strategy {
        Strategy::GenPasswords {
            charset,
            min_password_len,
            max_password_len,
            starting_password,
        } => Box::new(password_generator_iter(
            charset,
            min_password_len,
            max_password_len,
            starting_password,
            progress_bar,
        )),
        Strategy::PasswordFile(path) => Box::new(password_dictionary_reader_iter(path)),
        Strategy::MaskGenPasswords { mask } => Box::new(mask_password_iter(mask)),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn gpu_password_checker(
    gpu: GpuContext,
    file_path: &Path,
    file_number: usize,
    aes_info: AesInfo,
    strategy: Strategy,
    gpu_batch_size: u32,
    send_password_found: SyncSender<String>,
    stop_signal: Arc<AtomicBool>,
    progress_bar: ProgressBar,
) -> JoinHandle<()> {
    let file_path = file_path.to_owned();
    thread::Builder::new()
        .name("gpu-worker".to_string())
        .spawn(move || {
            let n_blocks = aes_info
                .derived_key_length
                .div_ceil(SHA1_OUTPUT_BYTES)
                .max(1) as u32;
            // GpuContext is supplied by the caller (already validated). The
            // only way Pbkdf2Context::new fails is via invalid argument
            // values, which we control here.
            let pctx = Pbkdf2Context::new(&gpu, gpu_batch_size, n_blocks)
                .expect("Pbkdf2Context::new with valid arguments");

            let mut iter = iterator_for_strategy(strategy, progress_bar.clone());

            // BufReader is enough — for AES we only re-enter the archive on
            // verifier hits (1-in-65k), so the whole-file Cursor that the
            // ZipCrypto CPU path uses isn't needed here.
            let archive_file = File::open(&file_path).expect("file should exist");
            let mut archive = ZipArchive::new(BufReader::new(archive_file))
                .expect("archive validated before-hand");
            let mut extraction_buffer = Vec::new();

            let batch_capacity = gpu_batch_size as usize;
            let mut batch: Vec<Vec<u8>> = Vec::with_capacity(batch_capacity);
            let salt = aes_info.salt;
            let verifier = aes_info.verification_value;
            let dk_len = aes_info.derived_key_length;

            loop {
                if stop_signal.load(Ordering::Relaxed) {
                    break;
                }

                batch.clear();
                for _ in 0..batch_capacity {
                    match iter.next() {
                        Some(pw) => batch.push(pw),
                        None => break,
                    }
                }
                if batch.is_empty() {
                    break;
                }

                let batch_refs: Vec<&[u8]> = batch.iter().map(Vec::as_slice).collect();
                let derived =
                    match pctx.derive(&batch_refs, &salt, WINZIP_AES_PBKDF2_ITERATIONS, dk_len) {
                        Ok(d) => d,
                        Err(e) => {
                            progress_bar.println(format!("GPU PBKDF2 failed: {e}"));
                            return;
                        }
                    };

                for (i, dk) in derived.iter().enumerate() {
                    if dk[dk_len - 2..] != verifier {
                        continue;
                    }
                    // 1/65536 false-positive rate — verify by full archive read.
                    let pw_bytes = &batch[i];
                    match archive.by_index_decrypt(file_number, pw_bytes) {
                        Err(ZipError::InvalidPassword) => continue,
                        Err(e) => panic!("Unexpected error {e:?}"),
                        Ok(zip) if zip.enclosed_name().is_none() => continue,
                        Ok(mut zip) => {
                            let zip_size = zip.size() as usize;
                            extraction_buffer.reserve(zip_size);
                            if let Ok(data_read) = zip.read_to_end(&mut extraction_buffer)
                                && data_read == zip_size
                            {
                                let password_str = String::from_utf8_lossy(pw_bytes).into_owned();
                                send_password_found
                                    .send(password_str)
                                    .expect("send found password should not fail");
                                return;
                            }
                            extraction_buffer.clear();
                        }
                    }
                }

                progress_bar.inc(batch.len() as u64);
            }
        })
        .unwrap()
}
