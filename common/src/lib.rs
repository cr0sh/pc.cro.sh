use aes::Aes256;
use anyhow::anyhow;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use chardetng::EncodingDetector;
use enum_kind::Kind;
use envs::*;
use hex_literal::hex;
use miniz_oxide::{deflate::compress_to_vec, inflate::decompress_to_vec_with_limit};
use regex::Regex;
use sha2::Digest;

mod envs;
mod optimizer;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;
const IV: [u8; 16] = include!("../iv.txt");

#[cfg(feature = "frontend")]
pub mod bindings {
    use crate::optimizer::optimizer_v1;

    use super::*;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub fn init() {
        std::panic::set_hook(Box::new(console_error_panic_hook::hook));
    }

    #[wasm_bindgen]
    pub async fn store_put(
        payload: Vec<u8>,
        key: String,
        passphrase: String,
        recaptcha_token: String,
    ) -> Result<(), JsValue> {
        let payload = into_utf8(&payload).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        let payload = String::from_utf8(payload).unwrap();
        let payload = optimizer_v1(&payload)
            .ok_or_else(|| JsValue::from_str("올바른 메이플스토리 설정 파일이 아닙니다."))?;
        let x = StoreFormat::V1(StoreFormatV1 {
            payload: payload.as_bytes().to_vec(),
        });
        x.upload(key, passphrase, recaptcha_token)
            .await
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub async fn store_get(
        key: String,
        passphrase: String,
        recaptcha_token: String,
        mmap_io: bool,
        memory_alloc_gigabytes: usize,
    ) -> Result<(), JsValue> {
        let mut s = StoreFormat::download(key, passphrase, recaptcha_token)
            .await
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        s.adjust_settings(mmap_io, memory_alloc_gigabytes)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Hash does not match")]
    HashMismatch,
    #[error("Payload too short")]
    InsufficientLength,
}

/// A value to be stored into Cloudflare KV.
#[derive(Kind)]
#[kind(functions(version = "u32"))]
pub enum StoreFormat {
    #[kind(version = "1")]
    V1(StoreFormatV1),
}

impl StoreFormat {
    #[cfg(feature = "frontend")]
    pub async fn upload(
        &self,
        key: String,
        passphrase: String,
        recaptcha_token: String,
    ) -> anyhow::Result<()> {
        use reqwest::StatusCode;

        match self {
            Self::V1(x) => {
                let x = x.encode_to_kv(passphrase.as_bytes())?;
                let client = reqwest::Client::new();
                let resp = client
                    .put(format!("{}/{}", CF_WORKER_BACKEND, &key))
                    .header("X-RECAPTCHA-TOKEN", recaptcha_token)
                    .body(x)
                    .send()
                    .await?;

                match resp.status() {
                    StatusCode::PAYLOAD_TOO_LARGE => Err(anyhow!("파일이 너무 큽니다")),
                    StatusCode::EXPECTATION_FAILED => Err(anyhow!("reCAPTCHA 인증에 실패했습니다")),
                    _ => Ok(()),
                }
            }
        }
    }

    #[cfg(feature = "frontend")]
    pub async fn download(
        key: String,
        passphrase: String,
        recaptcha_token: String,
    ) -> anyhow::Result<Self> {
        use anyhow::Context;
        use reqwest::StatusCode;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/{}", CF_WORKER_BACKEND, &key))
            .header("X-RECAPTCHA-TOKEN", recaptcha_token)
            .send()
            .await?;

        match resp.status() {
            StatusCode::NOT_FOUND => return Err(anyhow!("해당 이름을 가진 설정 파일이 없습니다")),
            StatusCode::EXPECTATION_FAILED => return Err(anyhow!("reCAPTCHA 인증에 실패했습니다")),
            _ => (),
        }

        let headers = resp.headers();
        let version = headers
            .get("X-ENCODING-VERSION")
            .map(|x| x.to_str())
            .transpose()?
            .map(str::parse)
            .unwrap_or(Ok(1))?;

        match version {
            1 => {
                let payload = resp.bytes().await?;
                let payload = base64::decode(&payload)?;

                Ok(Self::V1(
                    StoreFormatV1::decode_from_kv(&payload, passphrase.as_bytes())
                        .context("Cannot decode response payload")?,
                ))
            }
            x => Err(anyhow!("Unsupported encoding version {}", x)),
        }
    }

    pub fn adjust_settings(
        &mut self,
        mmap_io: bool,
        memory_alloc_gigabytes: usize,
    ) -> anyhow::Result<()> {
        let payload = match self {
            StoreFormat::V1(StoreFormatV1 { payload }) => payload,
        };

        let mmap_re = Regex::new(r#""MemoryMappedIO"=dword:([0-9a-fA-F]{8})"#).unwrap();
        let sixtyfourbit_re =
            Regex::new(r#""64bitFlushMemorySize"=dword:([0-9a-fA-F]{8})"#).unwrap();
        let exec_path_re = Regex::new(r#""ExecPath"=[^\n]+\r?\n"#).unwrap();
        let mut decoded = String::from_utf8(into_utf8(&payload)?).unwrap();

        let exec_path_range = exec_path_re
            .find(&decoded)
            .as_ref()
            .map(regex::Match::range);

        if let Some(r) = exec_path_range {
            decoded.replace_range(r, "");
        }

        let mmap_range = mmap_re
            .captures(&decoded)
            .map(|x| x.get(1).unwrap().range());

        if let Some(r) = mmap_range {
            decoded.replace_range(r, &format!("{:08x}", if mmap_io { 1 } else { 0 }));
        }

        let sixtyfourbit_range = sixtyfourbit_re
            .captures(&decoded)
            .map(|x| x.get(1).unwrap().range());

        if let Some(r) = sixtyfourbit_range {
            decoded.replace_range(r, &format!("{:08x}", memory_alloc_gigabytes * 1024));
        }

        payload.truncate(decoded.as_bytes().len());
        payload.copy_from_slice(decoded.as_bytes());

        Ok(())
    }
}

pub struct StoreFormatV1 {
    /// Windows registry value to store.
    payload: Vec<u8>,
}

impl StoreFormatV1 {
    pub fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }

    pub fn as_slice(&self) -> &[u8] {
        &*self.payload
    }

    pub fn encode_to_kv(&self, passphrase: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.payload);
        let payload_hash = hasher.finalize();

        let mut hasher = sha2::Sha256::new();
        hasher.update(passphrase);
        let passphrase = &*hasher.finalize();

        let it = self
            .payload
            .iter()
            .copied()
            .chain(payload_hash.iter().copied())
            .collect::<Vec<_>>();
        let compressed = compress_to_vec(&it, 10);
        println!("Compressed: {} bytes", compressed.len());
        let cipher = Aes256Cbc::new_from_slices(passphrase, &IV)?;
        Ok(cipher.encrypt_vec(&compressed))
    }

    pub fn decode_from_kv(x: &[u8], passphrase: &[u8]) -> anyhow::Result<Self> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(passphrase);
        let passphrase = &*hasher.finalize();

        let cipher = Aes256Cbc::new_from_slices(passphrase, &IV)?;
        let x = cipher.decrypt_vec(x)?;
        let payload_hash = decompress_to_vec_with_limit(&x, 4 << 20)
            .map_err(|x| anyhow!("Decompression failed: {:?}", x))?;
        if payload_hash.len() < 32 {
            return Err(Error::InsufficientLength.into());
        }
        let (payload, maybe_hash) = payload_hash.split_at(payload_hash.len() - 32);
        let mut hasher = sha2::Sha256::new();
        hasher.update(payload);
        let payload_hash = hasher.finalize();
        if &*payload_hash != maybe_hash {
            println!("{:?}, {:?}", &*payload_hash, maybe_hash);
            return Err(Error::HashMismatch.into());
        }

        let payload = payload.to_vec();

        Ok(Self { payload })
    }
}

pub fn into_utf8(x: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut detector = EncodingDetector::new();
    detector.feed(x, true);
    let enc = detector.guess(None, true);
    let mut decoder = enc.new_decoder();
    let mut buffer = vec![
        0;
        decoder
            .max_utf8_buffer_length_without_replacement(x.len())
            .ok_or_else(|| anyhow!("File size too big"))?
    ];
    let (result, _, written) = decoder.decode_to_utf8_without_replacement(x, &mut buffer, true);
    match result {
        encoding_rs::DecoderResult::InputEmpty => {
            buffer.truncate(written);
            Ok(buffer)
        }
        encoding_rs::DecoderResult::OutputFull => Err(anyhow!("Oops")),
        encoding_rs::DecoderResult::Malformed(_, _) => Err(anyhow!("File is malformed")),
    }
}
