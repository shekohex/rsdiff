use std::collections::HashMap;
use std::convert::TryInto;
use std::ops::Deref;

use blake2::{Blake2b, Digest};

/// An Adler-32 checksum modification with rolling operation.
/// it is not the same algorithm as Adler-32, but acts the same.
#[derive(Debug, Copy, Clone)]
pub struct RollingHasher {
    a: u32,
    b: u32,
    count: usize,
}

impl RollingHasher {
    pub const fn new() -> Self {
        Self {
            a: 0,
            b: 0,
            count: 0,
        }
    }

    /// return the current checksum digest calculated so far.
    #[inline]
    pub const fn digest(&self) -> u32 {
        (self.b << 16) | self.a
    }

    pub const fn count(&self) -> usize {
        self.count
    }

    /// Adds `bytes` to the checksum and update the internal calculated checksum.
    ///
    /// call [`RollingHasher::digest`] to get the result of the checksum.
    pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
        for b in bytes.as_ref() {
            self.insert(*b);
        }
    }

    #[inline(always)]
    pub fn insert(&mut self, byte: u8) {
        let bb = (byte as u32).wrapping_add(0xDEADC0DE);
        let a = self.a.wrapping_add(bb);
        let b = self.b.wrapping_add(a);
        self.a = a;
        self.b = b;
        self.count += 1;
    }

    /// Removes the given `byte` that was fed to the algorithm `size` bytes ago.
    pub fn remove(&mut self, byte: u8) {
        let bb = (byte as u32).wrapping_add(0xDEADC0DE);
        let c = self.count as u32;
        let a = self.a.wrapping_sub(bb);
        let b = self.b.wrapping_sub(c.wrapping_mul(bb));
        self.a = a;
        self.b = b;
        self.count -= 1;
    }

    /// Reset hasher instance to its initial state.
    pub fn reset(&mut self) {
        self.a = 1;
        self.b = 0;
    }
}

impl Default for RollingHasher {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to compute `hash` of the `bytes`.
/// It will handle hasher creation, data feeding and finalization.
pub fn weak_hash(bytes: impl AsRef<[u8]>) -> u32 {
    let mut hasher = RollingHasher::new();
    hasher.update(bytes);
    hasher.digest()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CryptoHash([u8; 32]);

impl Deref for CryptoHash {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct Signature<'a> {
    block_size: usize,
    blocks: Vec<BlockHash>,
    buffer: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct BlockHash {
    pub(crate) offset: usize,
    pub(crate) size: usize,
    pub(crate) weak_hash: u32,
    pub(crate) crypto_hash: CryptoHash,
}

#[derive(Debug, Clone)]
pub struct IndexedSignature {
    pub(crate) block_size: usize,
    pub(crate) blocks: HashMap<u32, BlockHash>,
}

impl<'a> Signature<'a> {
    pub const DEFAULT_BLOCK_SIZE: usize = 128;

    pub fn new(buffer: &'a [u8]) -> Self {
        Self::with_block_size(Self::DEFAULT_BLOCK_SIZE, buffer)
    }

    pub fn with_block_size(block_size: usize, buffer: &'a [u8]) -> Self {
        Self {
            block_size,
            blocks: Vec::with_capacity(buffer.len() / block_size),
            buffer,
        }
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    pub fn calculate(&mut self) {
        let buf = self.buffer;
        let mut blake2 = Blake2b::new();
        let chunks = buf.chunks(self.block_size);
        for chunk in chunks {
            let block_offset = chunk.as_ptr() as usize - self.buffer.as_ptr() as usize;
            let block_size = chunk.len();
            let block = &buf[block_offset..block_offset + block_size];
            let weak_hash = weak_hash(block);
            blake2.update(&block);
            let blake2_hash = blake2.finalize_reset();
            self.blocks.push(BlockHash {
                offset: block_offset,
                size: block_size,
                weak_hash,
                crypto_hash: CryptoHash(
                    blake2_hash[..32]
                        .try_into()
                        .expect("hash is greater than 32B"),
                ),
            });
        }
    }

    pub fn to_indexed(&self) -> IndexedSignature {
        let mut blocks = HashMap::with_capacity(self.blocks.len());
        for block in &self.blocks {
            blocks.insert(block.weak_hash, *block);
        }

        IndexedSignature {
            block_size: self.block_size,
            blocks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple() {
        assert_eq!(weak_hash([]), 0);
        assert_eq!(weak_hash([0]), 0xDEADC0DE << 16 | 0xDEADC0DE);
        assert_eq!(weak_hash([1]), (0xDEADC0DF) << 16 | 0xDEADC0DF);
    }

    #[test]
    fn wikipedia() {
        assert_eq!(weak_hash("Wikipedia"), 0xFCFBCB65);
    }

    #[test]
    fn rolling() {
        let buf = b"shekohex";
        let mut hasher = RollingHasher::new();
        hasher.update(buf);
        hasher.remove(b"s"[0]);
        assert_eq!(hasher.digest(), weak_hash("hekohex"));
        hasher.remove(b"h"[0]);
        assert_eq!(hasher.digest(), weak_hash("ekohex"));
        hasher.remove(b"e"[0]);
        assert_eq!(hasher.digest(), weak_hash("kohex"));
    }

    #[test]
    fn signature() {
        let buf = b"my name is shady khalifa";
        let mut signature = Signature::with_block_size(8, buf);
        signature.calculate();
        let indexed = signature.to_indexed();
        println!("{:#?}", indexed);
    }
}
