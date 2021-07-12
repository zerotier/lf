use std::mem::MaybeUninit;
use std::io::Read;

#[inline(always)]
pub(crate) fn read_array<R: Read, const S: usize>(r: &mut R) -> std::io::Result<[u8; S]> {
    let mut buf = unsafe { MaybeUninit::<[u8; S]>::uninit().assume_init() };
    let rr = r.read_exact(&mut buf);
    if rr.is_err() {
        std::io::Result::Err(rr.err().unwrap())
    } else {
        std::io::Result::Ok(buf)
    }
}

#[inline(always)]
pub(crate) fn read_array_with_size_prefix<R: Read, const S: usize>(r: &mut R) -> std::io::Result<[u8; S]> {
    if crate::varint::read(r)? == S as u64 {
        let mut buf = unsafe { MaybeUninit::<[u8; S]>::uninit().assume_init() };
        let rr = r.read_exact(&mut buf);
        if rr.is_err() {
            std::io::Result::Err(rr.err().unwrap())
        } else {
            std::io::Result::Ok(buf)
        }
    } else {
        std::io::Result::Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "size prefix does not match array size"))
    }
}

/*
#[inline(always)]
pub(crate) fn read_vec<R: Read>(r: &mut R, max_size: usize) -> std::io::Result<Vec<u8>> {
    let l = crate::varint::read(r)?;
    if l > max_size as u64 {
        return std::io::Result::Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "object too large"));
    }
    let mut v: Vec<u8> = Vec::new();
    v.resize(l as usize, 0);
    r.read_exact(v.as_mut_slice())?;
    std::io::Result::Ok(v)
}
*/
