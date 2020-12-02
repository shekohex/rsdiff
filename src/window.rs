//! Sliding window over immutable buffer.

use io::Read;
use std::{cmp, io, mem};

/// Sliding window over a buffer.
/// This maintains an internal buffer read from the original buffer.
pub struct Window<B: AsRef<[u8]>> {
    /// The front window buffer, contains at most `block_size` of bytes.
    front: Vec<u8>,
    /// The back window buffer, contains at most `block_size` of bytes.
    back: Vec<u8>,
    /// The block size used previously to create the original buffer signature.
    block_size: usize,
    /// The current read buffer offset (position).
    offset: usize,
    /// Maintains how much bytes we read so far.
    bytes_read: usize,
    /// The Window buffer.
    buffer: io::Cursor<B>,
}

impl<B: AsRef<[u8]>> Window<B> {
    /// Create a new window, it will try to fill the front and back buffer with at least size of
    /// block size bytes, if it fails it will return an io error.
    pub fn new(buffer: B, block_size: usize) -> io::Result<Self> {
        let mut buffer = io::Cursor::new(buffer);
        log::trace!("creating new window with block_size = {}", block_size);
        let mut front = vec![0; block_size];
        let mut back = vec![0; block_size];
        let size = buffer.read(&mut front)?;
        front.truncate(size);
        let size = buffer.read(&mut back)?;
        back.truncate(size);
        Ok(Window {
            front,
            back,
            block_size,
            buffer,
            offset: 0,
            bytes_read: 0,
        })
    }

    /// Slides the window byte by byte.
    /// this will change the offset +1 and the total bytes read +1.
    ///
    /// returning (tail, head)
    pub fn move_forword(&mut self) -> io::Result<(Option<u8>, Option<u8>)> {
        if self.front.is_empty() {
            return Ok((None, None));
        }
        if self.offset >= self.front.len() {
            if self.back.is_empty() {
                return Ok((None, None));
            }
            self.read_next()?;
        }
        let tail = self.tail();
        let head = self.head();
        self.offset += 1;
        self.bytes_read += 1;
        Ok((tail, head))
    }

    /// Peek the current frame.
    /// this will return (front, back) buffers from the current offset.
    ///
    ///```text
    /// Front Buffer:
    ///               [     Current View    ]
    ///               +---------------------+
    ///               |                     |
    /// +-------------|---------------------|-+
    /// |  |  |  |  | +  |  |  |  |  |  | + | |
    /// +-------------------------------------+
    ///
    /// Back Buffer:
    ///   [     Current View    ]
    ///   +---------------------+
    ///   |                     |
    /// +-|---------------------|-------------+
    /// | + |  |  |  |  |  |  | + |  |  |  |  |
    /// +-------------------------------------+
    ///```
    pub fn frame(&self) -> (&[u8], &[u8]) {
        let front_offset = cmp::min(self.offset, self.front.len());
        let back_offset = cmp::min(self.offset, self.back.len());
        (&self.front[front_offset..], &self.back[..back_offset])
    }

    /// Current frame size.
    /// Calculated by `front_frame_size` + `back_frame_size` - `current_read_offset`.
    pub fn frame_size(&self) -> usize {
        self.front.len() + self.back.len() - self.offset
    }

    /// are we still in a frame ?
    pub fn has_frame(&self) -> bool {
        self.frame_size() > 0
    }

    /// are we on the bonds of the current block (frame)?
    pub fn on_boundry(&self) -> bool {
        self.offset == 0 || self.offset == self.front.len()
    }

    /// get the total bytes read so far.
    pub fn bytes_read(&self) -> usize {
        self.bytes_read
    }

    fn head(&self) -> Option<u8> {
        let head_idx = self.offset + self.block_size - self.front.len();
        if head_idx >= self.back.len() {
            return None;
        }
        Some(self.back[head_idx])
    }

    fn tail(&self) -> Option<u8> {
        self.front.get(self.offset).cloned()
    }

    /// Read next block
    /// replace the current front buffer with the current back buffer.
    /// and read a new buffer into the back buffer then reset the read offset.
    fn read_next(&mut self) -> io::Result<()> {
        self.front = mem::replace(&mut self.back, vec![0; self.block_size]);
        let size = self.buffer.read(&mut self.back)?;
        self.back.truncate(size);
        self.offset = 0;
        Ok(())
    }
}
