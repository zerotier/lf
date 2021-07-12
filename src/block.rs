use std::io::{Write, Read};

use crate::sign::KeyPair;

#[derive(Clone, PartialEq, Eq)]
pub struct Block {
    pub id: [u8; 48],
    pub previous_id: [u8; 48],
    pub chain_id: [u8; 48],
    pub timestamp: u64,
    pub validator: [u8; crate::sign::P384_PUBLIC_KEY_SIZE],
    pub signature: [u8; crate::sign::P384_SIGNATURE_SIZE],
    pub entries: Vec<[u8; 48]>,
    pub work: [u8; crate::raven::PROOF_BYTES],
}

impl Block {
    fn calc_id(&mut self) {
        let b = self.to_vec();
        self.id = crate::sha384(&b);
    }

    /// Shortcut for read_from(slice).
    pub fn from_bytes(b: &[u8]) -> std::io::Result<Block> {
        let mut bb = b;
        Block::from_reader(&mut bb)
    }

    /// Read a block from a reader.
    pub fn from_reader<R: Read>(r: &mut R) -> std::io::Result<Block> {
        let mut blk = Block {
            id: [0_u8; 48],
            previous_id: crate::io::read_array(r)?,
            chain_id: crate::io::read_array(r)?,
            timestamp: crate::varint::read(r)?,
            validator: crate::io::read_array_with_size_prefix(r)?,
            signature: crate::io::read_array_with_size_prefix(r)?,
            entries: {
                let mut e: Vec<[u8; 48]> = Vec::new();
                let count = crate::varint::read(r)?;
                if count > crate::BLOCK_MAX_ENTRIES {
                    return std::io::Result::Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "block too large"));
                }
                e.reserve(count as usize);
                for _ in 0..count {
                    e.push(crate::io::read_array(r)?);
                }
                e
            },
            work: crate::io::read_array_with_size_prefix(r)?,
        };
        blk.calc_id();
        std::io::Result::Ok(blk)
    }

    fn write_to_intl<W: Write>(&self, w: &mut W, include_signature: bool, include_work: bool) -> std::io::Result<()> {
        // id is not written; it's computed on read or sign
        w.write_all(&self.previous_id)?;
        w.write_all(&self.chain_id)?;
        crate::varint::write(w, self.timestamp)?;
        crate::varint::write(w, self.validator.len() as u64)?;
        w.write_all(&self.validator)?;
        if include_signature {
            crate::varint::write(w, self.signature.len() as u64)?;
            w.write_all(&self.signature)?;
        }
        crate::varint::write(w, self.entries.len() as u64)?;
        for e in self.entries.iter() {
            w.write_all(e)?;
        }
        if include_work {
            crate::varint::write(w, self.work.len() as u64)?;
            w.write_all(&self.work)?;
        }
        std::io::Result::Ok(())
    }

    /// Write this block in binary format to a writer.
    pub fn write_to<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        self.write_to_intl(w, true, true)
    }

    /// Shortcut for write_to(a vector).
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.reserve(1024 + (self.entries.len() * 48));
        let _ = self.write_to_intl(&mut v, true, true);
        v
    }

    /// Perform sequential proof of work calculation.
    /// This of course can be very time consuming!
    pub fn work(&mut self, difficulty: u64) {
        let mut v: Vec<u8> = Vec::new();
        v.reserve(1024 + (self.entries.len() * 48));
        let _ = self.write_to_intl(&mut v, false, false);
        self.work = crate::raven::work(v.as_slice(), difficulty);
    }

    /// Sort entries and sign this block, filling out signature and id.
    /// Returns false if some kind of problem prevents signing (usually indicates a bug or major config problem).
    pub fn sign(&mut self, key: &KeyPair) -> bool {
        self.entries.sort();
        let mut v: Vec<u8> = Vec::new();
        v.reserve(1024 + (self.entries.len() * 48));
        let _ = self.write_to_intl(&mut v, false, true);
        let s = key.sign(v.as_slice());
        if s.is_some() {
            self.signature = s.unwrap();
            self.calc_id();
            true
        } else {
            false
        }
    }
}
