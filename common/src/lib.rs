use aes::Aes256;
use anyhow::anyhow;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use chardetng::EncodingDetector;
use enum_kind::Kind;
use envs::*;
use hex_literal::hex;
use miniz_oxide::{deflate::compress_to_vec, inflate::decompress_to_vec_with_limit};
use sha2::Digest;

mod envs;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;
const IV: [u8; 16] = include!("../iv.txt");

#[cfg(feature = "frontend")]
pub mod bindings {
    use super::*;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub async fn store_put(
        payload: Vec<u8>,
        key: String,
        passphrase: String,
        recaptcha_token: String,
    ) -> Result<(), JsValue> {
        let x = StoreFormat::V1(StoreFormatV1 { payload });
        x.upload(key, passphrase, recaptcha_token)
            .await
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
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

pub fn into_utf8(x: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let mut detector = EncodingDetector::new();
    detector.feed(&x, true);
    let enc = detector.guess(None, true);
    let mut decoder = enc.new_decoder();
    let mut buffer = vec![
        0;
        decoder
            .max_utf8_buffer_length_without_replacement(x.len())
            .ok_or_else(|| anyhow!("File size too big"))?
    ];
    let (result, _, written) = decoder.decode_to_utf8_without_replacement(&x, &mut buffer, true);
    match result {
        encoding_rs::DecoderResult::InputEmpty => {
            buffer.truncate(written);
            Ok(buffer)
        }
        encoding_rs::DecoderResult::OutputFull => Err(anyhow!("Oops")),
        encoding_rs::DecoderResult::Malformed(_, _) => Err(anyhow!("File is malformed")),
    }
}
