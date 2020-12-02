//! Rolling hash and Crypto hash.
//!
use std::collections::HashMap;
use std::convert::TryInto;
use std::ops::Deref;

use blake2::{Blake2b, Digest};

/// An Adler-32 checksum modification with rolling operation.
/// it is not the same algorithm as Adler-32, but acts similarly.
#[derive(Debug, Copy, Clone)]
pub struct RollingHasher {
    a: u32,
    b: u32,
    count: usize,
}

impl RollingHasher {
    /// Create a new `RollingHasher`.
    /// Everything is zero at first creation.
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

    /// returns how many bytes we rolled in so far.
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

    /// Rolling in a `byte`.
    /// Inserts the given `bytes` into the hash and updates the total count.
    #[inline(always)]
    pub fn insert(&mut self, byte: u8) {
        let bb = (byte as u32).wrapping_add(0xDEADC0DE);
        let a = self.a.wrapping_add(bb);
        let b = self.b.wrapping_add(a);
        self.a = a;
        self.b = b;
        self.count += 1;
    }
    /// Rolling out a `byte`.
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
        self.a = 0;
        self.b = 0;
        self.count = 0;
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

/// A [`Blake2b`] Crypto hash, with only the first 32 bytes of the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CryptoHash([u8; 32]);

impl CryptoHash {
    /// creates a new crypto hash from a given `hash`.
    ///
    /// ### Panics
    /// if the given `hash` bytes is not 32 bytes.
    ///
    /// for internal use only.
    pub(crate) fn new(hash: &[u8]) -> Self {
        Self(hash.try_into().expect("hash.len() >= 32 byte"))
    }
}

impl Deref for CryptoHash {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A Buffer Signature.
///
/// This represents a signature of a given buffer that can be used to calculate any changes
/// to this buffer without using the original itself.
///
/// see [`crate::delta::Delta`] for more examples.
#[derive(Clone)]
pub struct Signature<B: AsRef<[u8]>> {
    /// The Block Size that will be used to divide up the buffer into small chunks.
    /// this could be static, or dynamic depends on the creation of the signature.
    block_size: usize,
    /// Holds the calculated hash blocks so far.
    blocks: Vec<BlockHash>,
    /// The Original buffer.
    buffer: B,
    /// The Length of the original buffer.
    ///
    /// used to be handed over to the [`IndexedSignature`].
    original_buffer_len: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct BlockHash {
    pub(crate) weak_hash: u32,
    pub(crate) crypto_hash: CryptoHash,
}

/// A Small representation of the orignal [`Signature`].
/// this only holds the Hash blocks calculated using [`Signature::calculate`].
///
/// this signature can be serialized into any format and saved to local disk or sent over the
/// network to be then used to calculate the diff between a given buffer and the orignal one
/// without the need to have the original buffer itself.
#[derive(Debug, Clone)]
pub struct IndexedSignature {
    pub(crate) original_buffer_len: usize,
    pub(crate) block_size: usize,
    pub(crate) blocks: HashMap<u32, (usize, BlockHash)>,
}

impl<B: AsRef<[u8]>> Signature<B> {
    /// Create a new Signature with dynamic `block_size` depends on the given buffer size.
    ///
    /// see [`Signature::with_block_size`] for static `block_size`.
    pub fn new(buffer: B) -> Self {
        let block_size = calculate_block_size(buffer.as_ref().len());
        Self::with_block_size(block_size, buffer)
    }

    /// Create a new Signature with static `block_size`.
    ///
    /// this assets that the block size is not zero.
    /// see [`Signature::new`]` for dynamic `block_size`
    pub fn with_block_size(block_size: usize, buffer: B) -> Self {
        assert!(block_size != 0, "block size must be > 0");
        Self {
            block_size,
            blocks: Vec::with_capacity(buffer.as_ref().len() / block_size),
            original_buffer_len: buffer.as_ref().len(),
            buffer,
        }
    }

    /// get the block size used by this signature.
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Calculate the signature for the current buffer.
    ///
    /// this will divide the current buffer into small chunks each at least `block_size` of bytes.
    /// and then calculate for each block of them the crypto hash and the rolling hash.
    pub fn calculate(&mut self) {
        let buf = &self.buffer;
        let mut blake2 = Blake2b::new();
        let chunks = buf.as_ref().chunks(self.block_size);
        for chunk in chunks {
            let weak_hash = weak_hash(&chunk);
            blake2.update(&chunk);
            let blake2_hash = blake2.finalize_reset();
            let crypto_hash = CryptoHash::new(&blake2_hash[..32]);
            self.blocks.push(BlockHash {
                weak_hash,
                crypto_hash,
            });
        }
    }

    /// Convert the current Signature into the indexed one.
    /// this useful when you need to save the state of the current signature for sending over
    /// network or saving it to a file.
    ///
    /// also this used to calculate the [`crate::delta::Delta`] between two buffers.
    pub fn to_indexed(&self) -> IndexedSignature {
        let mut blocks = HashMap::with_capacity(self.blocks.len());
        for (i, block) in self.blocks.iter().enumerate() {
            blocks.insert(block.weak_hash, (i, *block));
        }

        IndexedSignature {
            block_size: self.block_size,
            blocks,
            original_buffer_len: self.original_buffer_len,
        }
    }
}

/// The recommended block_size is sqrt(original_buffer_len) with a 32 min size rounded
/// down to a multiple of the 128 byte.
///
/// similar to the original one in `rsync` code.
///
/// see: https://github.com/librsync/librsync/blob/1fd391c50719773bed09ad23013cd920f7606c47/src/sumset.c#L138
pub(crate) fn calculate_block_size(len: usize) -> usize {
    if len <= 32usize.pow(2) {
        32
    } else {
        ((len as f64).sqrt()) as usize & !127
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
