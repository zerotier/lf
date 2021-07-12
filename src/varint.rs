use std::io::{Write, Read};
use std::mem::MaybeUninit;

#[inline(always)]
pub fn write<W: Write>(w: &mut W, mut v: u64) -> std::io::Result<()> {
    let mut b = unsafe { MaybeUninit::<[u8; 16]>::uninit().assume_init() };
    let mut i = 0;
    loop {
        if v > 0x7f {
            b[i] = (v as u8) & 0x7f;
            i += 1;
            v >>= 7;
        } else {
            b[i] = (v as u8) | 0x80;
            i += 1;
            break;
        }
    }
    w.write_all(&b[0..i])
}

#[inline(always)]
pub fn read<R: Read>(r: &mut R) -> std::io::Result<u64> {
    let mut v = 0_u64;
    let mut bb = [0_u8; 1];
    for _ in 0..10 {
        let rr = r.read_exact(&mut bb);
        if rr.is_ok() {
            v >>= 7;
            let b = bb[0];
            if b <= 0x7f {
                v |= (b as u64) << 57;
            } else {
                v |= ((b & 0x7f) as u64) << 57;
                return std::io::Result::Ok(v);
            }
        } else {
            return std::io::Result::Err(rr.err().unwrap());
        }
    }
    std::io::Result::Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "varint read overrun"))
}
