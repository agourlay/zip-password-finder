use crate::gpu::GpuContext;
use crate::gpu::pbkdf2::{HMAC_BLOCK_BYTES, Pbkdf2Context, SHA1_OUTPUT_BYTES};
use crate::password_finder::Strategy;
use crate::password_gen::password_generator_iter;
use crate::password_mask::mask_password_iter;
use crate::password_reader::password_dictionary_reader_iter;
use crate::zip_utils::AesInfo;
use hmac::{Hmac, KeyInit, Mac};
use indicatif::ProgressBar;
use sha1::Sha1;
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

/// Confirm whether `derived_key` (PBKDF2 output for `password`, from GPU or CPU)
/// is the archive password. First the cheap 2-byte verifier, then — for a
/// zero-length entry, which the reader cannot authenticate — the WinZip
/// HMAC-SHA1-80 auth code, otherwise a full decrypt-and-read.
#[allow(clippy::too_many_arguments)]
fn key_confirms(
    derived_key: &[u8],
    password: &[u8],
    dk_len: usize,
    aes_key_length: usize,
    verifier: &[u8; 2],
    empty_entry_auth: Option<&[u8; 10]>,
    archive: &mut ZipArchive<BufReader<File>>,
    file_number: usize,
    extraction_buffer: &mut Vec<u8>,
) -> bool {
    if derived_key[dk_len - 2..] != *verifier {
        return false;
    }
    if let Some(expected_auth) = empty_entry_auth {
        // Empty entry: no ciphertext to authenticate, so verify the auth code.
        let hmac_key = &derived_key[aes_key_length..aes_key_length * 2];
        let mac =
            <Hmac<Sha1> as KeyInit>::new_from_slice(hmac_key).expect("HMAC accepts any key length");
        return mac.finalize().into_bytes()[..10] == *expected_auth;
    }
    // 1/65536 verifier false-positive rate — confirm by a full archive read.
    match archive.by_index_decrypt(file_number, password) {
        Err(ZipError::InvalidPassword) => false,
        Err(e) => panic!("Unexpected error {e:?}"),
        Ok(zip) if zip.enclosed_name().is_none() => false,
        Ok(mut zip) => {
            let zip_size = zip.size() as usize;
            extraction_buffer.reserve(zip_size);
            let confirmed = matches!(zip.read_to_end(extraction_buffer), Ok(n) if n == zip_size);
            extraction_buffer.clear();
            confirmed
        }
    }
}

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
            let aes_key_length = aes_info.aes_key_length;
            let empty_entry_auth = aes_info.empty_entry_auth;

            let send_found = |pw: &[u8]| {
                send_password_found
                    .send(String::from_utf8_lossy(pw).into_owned())
                    .expect("send found password should not fail");
            };

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

                // The GPU kernel only handles passwords up to one HMAC block.
                // Longer ones are rare (WinZip passwords are short) but must not
                // abort the run — derive their keys on the CPU instead.
                let gpu_batch: Vec<&[u8]> = batch
                    .iter()
                    .map(Vec::as_slice)
                    .filter(|pw| pw.len() <= HMAC_BLOCK_BYTES)
                    .collect();
                let derived =
                    match pctx.derive(&gpu_batch, &salt, WINZIP_AES_PBKDF2_ITERATIONS, dk_len) {
                        Ok(d) => d,
                        Err(e) => {
                            progress_bar.println(format!("GPU PBKDF2 failed: {e}"));
                            return;
                        }
                    };
                for (dk, pw) in derived.iter().zip(gpu_batch.iter()) {
                    if key_confirms(
                        dk,
                        pw,
                        dk_len,
                        aes_key_length,
                        &verifier,
                        empty_entry_auth.as_ref(),
                        &mut archive,
                        file_number,
                        &mut extraction_buffer,
                    ) {
                        send_found(pw);
                        return;
                    }
                }

                for pw in batch.iter().filter(|pw| pw.len() > HMAC_BLOCK_BYTES) {
                    let mut cpu_dk = vec![0u8; dk_len];
                    pbkdf2::pbkdf2::<Hmac<Sha1>>(
                        pw,
                        &salt,
                        WINZIP_AES_PBKDF2_ITERATIONS,
                        &mut cpu_dk,
                    )
                    .expect("PBKDF2 should not fail");
                    if key_confirms(
                        &cpu_dk,
                        pw,
                        dk_len,
                        aes_key_length,
                        &verifier,
                        empty_entry_auth.as_ref(),
                        &mut archive,
                        file_number,
                        &mut extraction_buffer,
                    ) {
                        send_found(pw);
                        return;
                    }
                }

                progress_bar.inc(batch.len() as u64);
            }
        })
        .unwrap()
}
