//! The [`Delta`] module.
//!
use std::fmt;
use std::io;
use std::mem;

use blake2::{Blake2b, Digest};
use log::trace;

use crate::hash::{CryptoHash, IndexedSignature, RollingHasher};
use crate::window::Window;

/// Operation to be done to upgrade from original version of the buffer to new version.
#[derive(Clone, Eq, PartialEq)]
pub enum Operation {
    /// Insertation Operation to be performed by inserting the `buffer` at the `offset`.
    Insert { buffer: Vec<u8>, offset: usize },
    /// Removeal Operation to be performed by removing the `len` bytes from the `buffer` starting
    /// at `offset` and going back.
    Remove { offset: usize, len: usize },
}

/// Debug formtaing for easier debugging in tests.
impl fmt::Debug for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Insert { buffer, offset } => {
                write!(f, "({}, {})", offset, String::from_utf8_lossy(buffer))
            }
            Operation::Remove { len, offset } => write!(f, "({}, {})", offset, len),
        }
    }
}

impl Operation {
    pub fn is_insert(&self) -> bool {
        matches!(self, Operation::Insert {..})
    }

    pub fn is_remove(&self) -> bool {
        matches!(self, Operation::Remove {..})
    }

    pub fn offset(&self) -> usize {
        match self {
            Operation::Insert { offset, .. } => *offset,
            Operation::Remove { offset, .. } => *offset,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Operation::Insert { buffer, .. } => buffer.len(),
            Operation::Remove { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Current Operation buffer, returns [`None`] if the operation is [`Operation::Remove`].
    pub fn buffer(&self) -> Option<&[u8]> {
        match self {
            Operation::Insert { buffer, .. } => Some(&buffer),
            _ => None,
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Insert { offset, buffer } => write!(
                f,
                "+ {}..{} = {}",
                offset,
                offset + buffer.len(),
                String::from_utf8_lossy(&buffer)
            ),
            Operation::Remove { offset, len } => write!(f, "- {}..-{}", offset, len),
        }
    }
}

/// Delta between two buffers, this dose not require the original buffer, but instead it only needs
/// the original buffer signature, from there with the new modified buffer we can calculate the
/// operations needed to upgrade the original to match the new modified one.
#[derive(Debug, Clone)]
pub struct Delta {
    /// Indexed Singature is just like the [`crate::hash::Signature`] but can indexed by Block used to calculate
    /// this signature and can be located using the `weak_hash` form [`crate::hash::RollingHasher`].
    sig: IndexedSignature,
    /// The [`Operation`]s calculated by calling [`Delta::diff`] on the new buffer.
    ops: Vec<Operation>,
}

impl Delta {
    /// Create new [`Delta`].
    /// ### Example
    /// ```
    /// use rsdiff::{Signature, Delta};
    ///
    /// let original = "Hello from the other side!";
    /// // create a new signature with the original buffer.
    /// let mut signature = Signature::new(original);
    /// // calculate the signature
    /// signature.calculate();
    /// let new = "Hello from this side!";
    /// let mut delta = Delta::new(signature.to_indexed());
    /// // then you can calculate the delta by calling
    /// delta.diff(new);
    ///
    /// ```
    pub const fn new(signature: IndexedSignature) -> Self {
        Self {
            sig: signature,
            ops: Vec::new(),
        }
    }
    /// Get the operations calculated so far.
    ///
    /// see [`Delta::into_operations`] if you don't need the [`Delta`] anymore.
    pub fn operations(&self) -> &[Operation] {
        &self.ops
    }

    /// Consume `Self` and returns the operations to be then used for patching.
    ///
    /// see [`Delta::operations`] if you don't want to consume the `Self`.
    pub fn into_operations(self) -> Vec<Operation> {
        self.ops
    }

    /// Calculate the diff between the original and modified buffers.
    ///
    /// Retuns Err in case if there is any IO operation failled.
    pub fn diff(&mut self, buf: impl AsRef<[u8]>) -> io::Result<()> {
        trace!("starting new diff");
        let block_size = self.sig.block_size;
        trace!("block_size = {}", block_size);
        let original_buf_len = self.sig.original_buffer_len;
        trace!("original_buf_len = {}", original_buf_len);
        let mut window = Window::new(buf, block_size)?;
        let mut hasher = RollingHasher::new();
        let mut ins_buffer = Vec::new();
        let mut last_matching_block_idx = -1;
        trace!("last_matching_block_idx = {}", last_matching_block_idx);
        hasher.update(window.frame().0);
        trace!("start diff loop..");
        while window.has_frame() {
            let block_idx = self.find_match(hasher.digest(), &window, last_matching_block_idx);
            trace!("block_idx = {:?}", block_idx);
            trace!("current total bytes read: {}", window.bytes_read());
            if let Some(block_idx) = block_idx {
                if !ins_buffer.is_empty() {
                    trace!(
                        "insert buffer is not empty, add insert op with len: {}",
                        ins_buffer.len()
                    );
                    self.add_insert_op(
                        window.bytes_read() - ins_buffer.len(),
                        mem::replace(&mut ins_buffer, Vec::new()),
                    );
                }
                trace!("check if the current block id is greater than last matched one");
                if block_idx as isize > last_matching_block_idx + 1 {
                    trace!("okay, it is greater, add a remove op");
                    let block_len = block_idx as isize - last_matching_block_idx - 1;
                    let len = block_size as isize * block_len;
                    self.add_remove_op(window.bytes_read(), len as usize);
                }
                trace!(
                    "update last matched block id ({}) with the current matched block id ({})",
                    last_matching_block_idx,
                    block_idx
                );
                last_matching_block_idx = block_idx as isize;
                trace!("move a block forword with block_size = {}", block_size);
                for _ in 0..block_size {
                    trace!("current total bytes read: {}", window.bytes_read());
                    if window.on_boundry() && window.frame_size() == 0 {
                        trace!("we hit the bounds and current frame size is zero; break");
                        break;
                    }
                    trace!("move the window one byte forword ..");
                    let (tail, head) = window.move_forword()?;
                    if let Some(tail) = tail {
                        trace!("rolling out the hash ..");
                        hasher.remove(tail);
                    }

                    if let Some(head) = head {
                        trace!("rolling in the hash ..");
                        hasher.insert(head);
                    }
                }
                trace!(
                    "moved a block, current total bytes read so far: {}",
                    window.bytes_read()
                );
            } else {
                trace!("no match found, moving the window forword one byte ..");
                let (tail, head) = window.move_forword()?;
                trace!("current total bytes read: {}", window.bytes_read());
                if let Some(tail) = tail {
                    trace!("rolling out the hash ..");
                    hasher.remove(tail);
                    trace!("add the current tail to the insert buffer ..");
                    ins_buffer.push(tail);
                }
                if let Some(head) = head {
                    trace!("rolling in the hash ..");
                    hasher.insert(head);
                }
            }
        }

        trace!("diff loop ended.");
        trace!("current total bytes read: {}", window.bytes_read());
        trace!(
            "check the insert buffer for any remaining bytes, len = {}",
            ins_buffer.len()
        );
        if !ins_buffer.is_empty() {
            self.add_insert_op(window.bytes_read() - ins_buffer.len(), ins_buffer);
        }

        let original_block_count = (original_buf_len + block_size - 1) / block_size;
        trace!("checking if the last matched block is less than the original block count which means a remove op should be added!");
        trace!("original block count = {}", original_block_count);
        trace!("last matching block = {}", last_matching_block_idx + 1);
        if last_matching_block_idx + 1 < original_block_count as isize {
            let block_len = (last_matching_block_idx + 1) * block_size as isize;
            let len = original_buf_len as isize - block_len;
            self.add_remove_op(window.bytes_read(), len as usize);
        }
        Ok(())
    }

    fn add_insert_op(&mut self, offset: usize, buffer: Vec<u8>) {
        trace!(
            "Insert: at {} with len {} and buf = {} {:?}",
            offset,
            buffer.len(),
            String::from_utf8_lossy(&buffer),
            buffer
        );
        self.ops.push(Operation::Insert { offset, buffer });
    }

    fn add_remove_op(&mut self, offset: usize, len: usize) {
        trace!("Remove: at {} with len {}", offset, len,);
        self.ops.push(Operation::Remove { offset, len });
    }

    /// Try to find a matched block from the original buffer signature.
    /// if so, it will try to find if the current block index is the same as the one we matched.
    /// if so, it is not modified, but if it fails these condations, it means there is a
    /// modification happened in this block.
    fn find_match<B: AsRef<[u8]>>(
        &self,
        weak_hash: u32,
        window: &Window<B>,
        last_matching_block_idx: isize,
    ) -> Option<usize> {
        trace!("weak_hash of the current frame = 0x{:0x}", weak_hash);
        match self.sig.blocks.get(&weak_hash) {
            Some((idx, block)) => {
                trace!("found a match with the weak hash !!!");
                let mut blake2 = Blake2b::new();
                let (front, back) = window.frame();
                blake2.update(front);
                blake2.update(back);
                let result = blake2.finalize();
                let crypto_hash = CryptoHash::new(&result[..32]);
                trace!("comparing the crypto hash");
                let crypto_match = block.crypto_hash == crypto_hash;
                let new_idx = *idx as isize > last_matching_block_idx;
                trace!("crypto_match ? {}", crypto_match);
                trace!("new_idx ? {}", new_idx);
                if crypto_match && new_idx {
                    trace!("all matched !!!");
                    Some(*idx)
                } else {
                    trace!("crypto hash did not match, skip ..");
                    None
                }
            }
            None => None,
        }
    }
}
