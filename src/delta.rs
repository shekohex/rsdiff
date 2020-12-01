use std::collections::HashMap;

use blake2::{Blake2b, Digest};

use crate::hash::{BlockHash, IndexedSignature, RollingHasher};

/// A Sliding window over the input buffer.
#[derive(Debug, Copy, Clone)]
struct Window {
    start: usize,
    end: usize,
}

impl Window {
    const fn zero() -> Self {
        Self::new(0, 0)
    }
    const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    const fn size(&self) -> usize {
        self.end - self.start
    }

    fn shift(&mut self) {
        self.start = self.end;
    }
}

/// Holds the properties of the current [`Op`].
#[derive(Debug, Copy, Clone)]
pub struct OpProps {
    /// The Offset in the Original Source.
    pub source: usize,
    /// The Offset in the Target Patch Source,
    pub target: usize,
    /// How many bytes needed to be copied over from the offset of the source to the offset of the
    /// tartget.
    pub len: usize,
}

impl OpProps {
    fn merge(&mut self, other: &mut OpProps) {
        self.target = other.target;
        self.source = other.source;
        self.len += other.len;
        other.len = 0;
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Op {
    Keep(OpProps),
    Overwrite(OpProps),
}

impl Op {
    pub const fn keep(source: usize, target: usize, len: usize) -> Op {
        Op::Keep(OpProps {
            source,
            target,
            len,
        })
    }

    pub const fn overwrite(source: usize, target: usize, len: usize) -> Op {
        Op::Overwrite(OpProps {
            source,
            target,
            len,
        })
    }

    pub const fn is_keep(&self) -> bool {
        matches!(self, Op::Keep(_))
    }

    pub const fn is_overwrite(&self) -> bool {
        matches!(self, Op::Overwrite(_))
    }

    pub fn target(&self) -> usize {
        match *self {
            Op::Keep(prop) => prop.target,
            Op::Overwrite(prop) => prop.target,
        }
    }

    pub fn source(&self) -> usize {
        match *self {
            Op::Keep(prop) => prop.source,
            Op::Overwrite(prop) => prop.source,
        }
    }

    pub fn len(&self) -> usize {
        match *self {
            Op::Keep(prop) => prop.len,
            Op::Overwrite(prop) => prop.len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn merge(&mut self, other: &mut Self) {
        match self {
            Op::Keep(prop) => prop.merge(other.props_mut()),
            Op::Overwrite(prop) => prop.merge(other.props_mut()),
        }
    }

    pub fn props(&self) -> OpProps {
        match *self {
            Op::Keep(prop) => prop,
            Op::Overwrite(prop) => prop,
        }
    }

    fn props_mut(&mut self) -> &mut OpProps {
        match self {
            Op::Keep(prop) => prop,
            Op::Overwrite(prop) => prop,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Delta<'a> {
    signature: IndexedSignature,
    buffer: &'a [u8],
    ops: Vec<Op>,
}

impl<'a> Delta<'a> {
    pub fn new(signature: IndexedSignature, buffer: &'a [u8]) -> Self {
        Self {
            signature,
            buffer,
            ops: Vec::new(),
        }
    }

    pub fn buffer(&self) -> &[u8] {
        self.buffer
    }

    pub fn calculate(&mut self) {
        let block_size = self.signature.block_size;
        let blocks = &self.signature.blocks;
        let buf = self.buffer;
        let mut base_map = HashMap::new();
        let mut hasher = RollingHasher::new();
        let mut window = Window::zero();
        let hashes_len = (buf.len() + block_size - 1) / block_size;
        let mut hashes = Vec::with_capacity(hashes_len);
        hashes.reserve(hashes_len);
        loop {
            let remaining = buf.len() - window.start;
            if remaining == 0 {
                break;
            }
            let current_window_size = std::cmp::min(remaining, block_size);
            while hasher.count() < current_window_size {
                hasher.insert(buf[window.end]);
                window.end += 1;
            }
            match self.find(&window, hasher.digest()) {
                Some(block) => {
                    window.shift();
                    hasher.reset();
                    base_map.insert(block.crypto_hash, block.offset);
                    hashes.push(block.crypto_hash);
                }
                None => {
                    hasher.remove(buf[window.start]);
                    window.start += 1;
                }
            }
        }

        if hashes.len() == blocks.len() {
            let mut matched = true;
            for e in hashes.iter().zip(blocks.values()) {
                if *e.0 != e.1.crypto_hash {
                    matched = false;
                    break;
                }
            }

            if matched {
                // no changes
                return;
            }
        }

        for block in blocks.values() {
            match base_map.get(&block.crypto_hash) {
                Some(offset) => {
                    self.ops.push(Op::keep(*offset, block.offset, block.size));
                }
                None => {
                    self.ops
                        .push(Op::overwrite(block.offset, block.offset, block.size));
                }
            }
        }
        self.optimize();
    }

    pub fn operations(&self) -> &[Op] {
        &self.ops
    }

    fn find(&self, window: &Window, weak_hash: u32) -> Option<BlockHash> {
        let blocks = &self.signature.blocks;
        if let Some(block) = blocks.get(&weak_hash) {
            let slice = &self.buffer[window.start..window.end];
            let mut blake2 = Blake2b::new();
            blake2.update(slice);
            let blake2_hash = blake2.finalize();
            if blake2_hash[..32] == *block.crypto_hash {
                let block = BlockHash {
                    offset: window.start,
                    size: window.size(),
                    crypto_hash: block.crypto_hash,
                    weak_hash,
                };
                Some(block)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub(crate) fn optimize(&mut self) {
        let mut overwrites = self
            .ops
            .iter()
            .filter(|op| op.is_overwrite())
            .cloned()
            .collect();
        let mut keeps = self.ops.iter().filter(|op| op.is_keep()).cloned().collect();
        Self::optimize_ops(&mut overwrites);
        Self::optimize_ops(&mut keeps);
        self.ops.clear();
        self.ops.extend(keeps);
        self.ops.extend(overwrites);
    }

    pub(crate) fn optimize_ops(ops: &mut Vec<Op>) {
        if !ops.is_empty() {
            ops.sort_by_key(|op| op.target());
            let (mut prev, tail) = ops.split_first_mut().unwrap();
            for n in tail.iter_mut() {
                if prev.source() + prev.len() == n.source()
                    && prev.target() + prev.len() == n.target()
                    && prev.len() + n.len() < usize::MAX
                {
                    n.merge(prev);
                }
                prev = n;
            }
            ops.retain(|op| !op.is_empty());
        }
    }
}
