#[macro_use]
extern crate lazy_static;

use std::convert::TryInto;
use std::os::raw::{c_int, c_void};
use std::io::Write;
use std::ptr::copy_nonoverlapping;

use gmp::mpz::{Mpz, ProbabPrimeResult};
use std::ops::{DivAssign, RemAssign};

/// Length of a proof in bytes. This is 2X the length of G in bytes.
const GROUP_SIZE_BYTES: usize = 8192;
pub const PROOF_BYTES: usize = (GROUP_SIZE_BYTES * 2) + 8;

#[allow(non_camel_case_types)]
#[repr(C)]
struct mpz_struct {
    _mp_alloc: c_int,
    _mp_size: c_int,
    _mp_d: *mut usize
}

// ZeroTier-generated 8192-bit semiprime modulus G of unknown order.
// This is a product of two random safe primes that were subsequently deleted.
lazy_static! {
    static ref GROUP : Mpz = Mpz::from_str_radix(include_str!("raven-group.hex"), 16).unwrap();
    static ref BASE : Mpz = Mpz::from(3);
}

// Hashing of multi-precision integers assumes 64-bit limbs in little endian order.
// It's done this way to avoid additional memory copies.
// For 32-bit or big-endian machines a different version would have to be written that performs conversions.
#[cfg(all(target_endian = "little", target_pointer_width = "64"))]
#[inline(always)]
fn write_mpz_bits<W: Write>(w: &mut W, mpz: &Mpz) -> std::io::Result<()> {
    let mpz_inner: *const mpz_struct = unsafe { mpz.inner().cast() };
    let mut mpz_size = unsafe { ((*mpz_inner)._mp_size as usize) * 8 };
    let mpz_d = mpz_inner._mp_d.cast::<u8>();
    if mpz_size > 0 && !mpz_d.is_null() {
        w.write_all(unsafe { std::slice::from_raw_parts(mpz_d, mpz_size) })
    } else {
        std::io::Result::Ok(())
    }
}

#[inline(always)]
fn hash_results_to_prime(exp: &Mpz, result: &Mpz) -> Mpz {
    let mut h = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha384()).unwrap();
    let _ = write_mpz_bits(&mut h, &BASE);
    let _ = write_mpz_bits(&mut h, exp);
    let _ = write_mpz_bits(&mut h, result);
    Mpz::from(h.finish().unwrap().as_ref()).nextprime()
}

fn create_big_exponent(challenge: &[u8], difficulty: usize) -> Mpz {
    let challenge = crate::sha384(challenge);
    let mut ctr = openssl::symm::Crypter::new(openssl::symm::Cipher::aes_256_ctr(), openssl::symm::Mode::Encrypt, &challenge[0..32], Some(&challenge[32..48])).unwrap();
    if difficulty > 0 {
        let layout = std::alloc::Layout::from_size_align(difficulty * 16, 16).unwrap();
        let mut buf_mem = unsafe { std::alloc::alloc_zeroed(layout) };
        if !buf_mem.is_null() {
            let buf = unsafe { std::slice::from_raw_parts_mut(buf_mem, layout.size()) };
            ctr.update(buf, buf);
            let exp = Mpz::from(buf);
            unsafe { std::alloc::dealloc(buf_mem, layout) };
            exp
        } else {
            Mpz::from(1)
        }
    } else {
        Mpz::from(1)
    }
}

/// Perform work and return a succinct proof that can be quickly verified without performing full exponentiation.
pub fn work(challenge: &[u8], difficulty: u64) -> [u8; PROOF_BYTES] {
    let mut exp = create_big_exponent(challenge, difficulty as usize);
    let result: Mpz = BASE.powm(&exp, &GROUP);
    exp.div_assign(hash_results_to_prime(&exp, &result));
    let proof: Mpz = BASE.powm(&exp, &GROUP);
    drop(exp);

    let proof_bytes: Vec<u8> = Vec::from(&proof);
    let result_bytes: Vec<u8> = Vec::from(&result);
    let difficulty_bytes = difficulty.to_le_bytes();

    debug_assert!(proof_bytes.len() < GROUP_SIZE_BYTES, "proof is larger than group size, should be impossible");
    debug_assert!(result_bytes.len() < GROUP_SIZE_BYTES, "result is larger than group size, should be impossible");

    let mut output = [0_u8; PROOF_BYTES];
    output[(GROUP_SIZE_BYTES - proof_bytes.len())..GROUP_SIZE_BYTES].copy_from_slice(proof_bytes.as_slice());
    output[(GROUP_SIZE_BYTES - result_bytes.len())..(GROUP_SIZE_BYTES * 2)].copy_from_slice(result_bytes.as_slice());
    output[(GROUP_SIZE_BYTES * 2)..PROOF_BYTES].copy_from_slice(&difficulty_bytes);
    output
}

/// Verify a supplied proof of sequential work and return difficulty or 0 if proof is invalid.
pub fn verify(challenge: &[u8], proof: &[u8]) -> u64 {
    if proof.len() == PROOF_BYTES {
        let difficulty = u64::from_le_bytes((&proof[(GROUP_SIZE_BYTES * 2)..PROOF_BYTES]).try_into().unwrap());
        let mut exp = create_big_exponent(challenge, difficulty as usize);
        let result = Mpz::from(&proof[(PROOF_BYTES / 2)..PROOF_BYTES]);
        exp.rem_assign(hash_results_to_prime(&exp, &result));
        if (proof.powm(&exp, &GROUP) * base.powm(&exp, &GROUP)).modulus(&GROUP) == *result {
            difficulty
        } else {
            0
        }
    } else {
        0
    }
}
