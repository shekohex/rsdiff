//! Patching buffer using operations.
//! this is not ready yet!
//! it is a bit messy so never mind reading it.
use log::trace;
use std::mem;
use std::str::Utf8Error;

use crate::delta::Operation;

#[derive(Debug, Clone)]
pub struct Patch<O: AsRef<[Operation]>> {
    buffer: Vec<u8>,
    ops: O,
}

impl<O: AsRef<[Operation]>> Patch<O> {
    pub fn new(ops: O) -> Self {
        Self {
            buffer: Vec::new(),
            ops,
        }
    }

    pub fn apply(&mut self, original: impl AsRef<[u8]>) -> bool {
        trace!("starting new patch with {} op", self.ops.as_ref().len());
        // noting to patch
        if self.ops.as_ref().is_empty() {
            trace!("noting here to patch !");
            return false;
        }
        let mut original_buffer = original.as_ref().iter();
        trace!("creating new empty buffer for the patched buffer");
        let mut patched = Vec::new();
        // seprate the operations.
        let inserts = self.ops.as_ref().iter().filter(|op| op.is_insert());
        let removes = self.ops.as_ref().iter().filter(|op| op.is_remove());
        let mut idx = 0;
        trace!("starting by the inserts ops first ..");
        for op in inserts {
            trace!("current idx: {}", idx);
            trace!("Insert {}", op);
            while idx < op.offset() {
                if let Some(b) = original_buffer.next() {
                    patched.push(*b);
                    idx += 1;
                } else {
                    break;
                }
            }
            let changes = op.buffer().unwrap();
            patched.extend(changes);
            idx += changes.len();
        }
        trace!("done with inserts ops ..");
        patched.extend(original_buffer);
        trace!("switching buffers (original <-> patched)");
        let original_buffer = mem::replace(&mut patched, Vec::new());
        let mut original_buffer = original_buffer.iter();
        idx = 0;
        trace!("starting removes ops ..");
        for op in removes {
            trace!("current idx: {}", idx);
            trace!("Remove {}", op);
            while idx < op.offset() {
                if let Some(b) = original_buffer.next() {
                    patched.push(*b);
                    idx += 1;
                } else {
                    break;
                }
            }
            trace!("skipping {} bytes..", op.len());
            for _ in 0..op.len() {
                original_buffer.next();
            }
        }

        patched.extend(original_buffer);
        self.buffer = patched;
        self.buffer.is_empty()
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub fn buffer_utf8(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(&self.buffer)
    }
}
