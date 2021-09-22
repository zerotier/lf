use std::convert::TryInto;

use openssl::ec::{EcGroup, EcPoint, EcKey};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use std::ops::DerefMut;

pub const SIGNATURE_ALGORITHM_TYPE_P384: u8 = 1;

pub const P384_PUBLIC_KEY_SIZE: usize = 50; // type + point compressed key
pub const P384_SECRET_KEY_SIZE: usize = 48;
pub const P384_KEY_PAIR_SIZE: usize = P384_PUBLIC_KEY_SIZE + P384_SECRET_KEY_SIZE;
pub const P384_SIGNATURE_SIZE: usize = 96;

#[derive(Clone, PartialEq, Eq)]
pub struct KeyPair(pub [u8; P384_KEY_PAIR_SIZE]);

/// A NIST P-384 key pair.
/// Other algorithms could be supported in the future.
impl KeyPair {
    pub fn generate() -> KeyPair {
        crate::BIGNUM_CONTEXT.with(|ctx| {
            let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();
            let p384 = openssl::ec::EcKey::generate(group.as_ref()).unwrap();
            let p384_pub = p384.public_key().to_bytes(group.as_ref(), openssl::ec::PointConversionForm::COMPRESSED, ctx.borrow_mut().deref_mut()).unwrap();
            let p384_private = p384.private_key().to_vec();
            let mut kp = KeyPair([0_u8; P384_KEY_PAIR_SIZE]);
            kp.0[0] = SIGNATURE_ALGORITHM_TYPE_P384;
            kp.0[1 + (49 - p384_pub.len())..P384_PUBLIC_KEY_SIZE].copy_from_slice(p384_pub.as_slice());
            kp.0[P384_PUBLIC_KEY_SIZE + (P384_SECRET_KEY_SIZE - p384_private.len())..P384_KEY_PAIR_SIZE].copy_from_slice(p384_private.as_slice());
            kp
        })
    }

    #[inline(always)]
    pub fn public_bytes(&self) -> [u8; P384_PUBLIC_KEY_SIZE] {
        self.0[0..P384_PUBLIC_KEY_SIZE].try_into().unwrap()
    }

    #[inline(always)]
    pub fn algorithm_type(&self) -> u8 {
        self.0[0]
    }

    #[inline(always)]
    pub fn key_pair_bytes(&self) -> &[u8; P384_KEY_PAIR_SIZE] {
        &self.0
    }

    pub fn sign(&self, msg: &[u8]) -> Option<[u8; P384_SIGNATURE_SIZE]> {
        crate::BIGNUM_CONTEXT.with(|ctx| {
            let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
            let p384_pub = EcPoint::from_bytes(group.as_ref(), &self.0[1..P384_PUBLIC_KEY_SIZE], ctx.borrow_mut().deref_mut());
            if p384_pub.is_err() {
                return None;
            }
            let p384_pub = p384_pub.unwrap();
            let p384_private = BigNum::from_slice(&self.0[P384_PUBLIC_KEY_SIZE..P384_KEY_PAIR_SIZE]);
            if p384_private.is_err() {
                return None;
            }
            let p384_private = p384_private.unwrap();
            let p384 = EcKey::from_private_components(group.as_ref(), p384_private.as_ref(), p384_pub.as_ref());
            if p384.is_err() {
                return None;
            }
            let p384 = p384.unwrap();

            let digest_384 = crate::sha384(msg);
            let p384s = EcdsaSig::sign(digest_384.as_ref(), p384.as_ref());
            if p384s.is_err() {
                return None;
            }
            let p384s = p384s.unwrap();

            let p384sr = p384s.r().to_vec();
            let p384ss = p384s.s().to_vec();
            let mut sig = [0_u8; P384_SIGNATURE_SIZE];
            sig[(48 - p384sr.len())..48].copy_from_slice(p384sr.as_slice());
            sig[48 + (48 - p384sr.len())..96].copy_from_slice(p384ss.as_slice());
            Some(sig)
        })
    }
}

/// Get algorithm type from a public key or key pair, returns type or 0 if not valid.
#[inline(always)]
pub fn key_algorithm_type(key: &[u8]) -> u8 {
    if !key.is_empty() {
        key[0]
    } else {
        0
    }
}

pub fn verify_signature(msg: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    if public_key.len() != P384_PUBLIC_KEY_SIZE || public_key[0] != SIGNATURE_ALGORITHM_TYPE_P384 || signature.len() != P384_SIGNATURE_SIZE {
        return false;
    }
    crate::BIGNUM_CONTEXT.with(|ctx| {
        let p384sr = BigNum::from_slice(&signature[0..48]);
        if p384sr.is_err() {
            return false;
        }
        let p384sr = p384sr.unwrap();
        let p384ss = BigNum::from_slice(&signature[48..96]);
        if p384ss.is_err() {
            return false;
        }
        let p384ss = p384ss.unwrap();
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let p384_pub = EcPoint::from_bytes(group.as_ref(), &public_key[1..P384_PUBLIC_KEY_SIZE], ctx.borrow_mut().deref_mut());
        if p384_pub.is_err() {
            return false;
        }
        let p384 = EcKey::from_public_key(group.as_ref(), p384_pub.as_ref().unwrap());
        if p384.is_err() {
            return false;
        }
        let p384s = EcdsaSig::from_private_components(p384sr, p384ss);
        if p384s.is_err() {
            return false;
        }
        p384s.unwrap().verify(msg, p384.as_ref().unwrap()).unwrap_or(false)
    })
}
