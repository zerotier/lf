pub mod sign;
pub mod varint;
pub mod error;
pub mod block;

mod config;
mod io;
mod raven;

pub use config::Config;

use std::io::Read;
use std::convert::TryInto;

pub const BLOCK_MAX_ENTRIES: u64 = 1024 * 1024;

thread_local! {
    pub(crate) mut static BIGNUM_CONTEXT: BigNumContext = BigNumContext::new().unwrap();
}

/// Compute SHA384 using openssl library (glue code)
#[inline(always)]
pub fn sha384(input: &[u8]) -> [u8; 48] {
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha384(), input).unwrap();
    digest.as_ref().try_into().unwrap()
}
