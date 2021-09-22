#![allow(dead_code)]

#[cfg(feature = "frontend")]
pub(crate) const CF_WORKER_BACKEND: &str = "http://localhost:8787/api";

pub(crate) const RECAPTCHA_SECRET: &str = include_str!("../../RECAPTCHA_SECRET");
