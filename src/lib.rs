#[macro_use]
extern crate lazy_static;

pub mod sign;
pub mod varint;
pub mod error;
pub mod block;
pub mod raven;

pub(crate) mod config;
pub(crate) mod io;

pub use config::Config;

use std::convert::TryInto;

pub const BLOCK_MAX_ENTRIES: u64 = 1024 * 1024;

thread_local! {
    pub(crate) static BIGNUM_CONTEXT: std::cell::RefCell<openssl::bn::BigNumContext> = std::cell::RefCell::new(openssl::bn::BigNumContext::new().unwrap());
}

/// Compute SHA384 using openssl library (glue code)
#[inline(always)]
pub fn sha384(input: &[u8]) -> [u8; 48] {
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha384(), input).unwrap();
    digest.as_ref().try_into().unwrap()
}
