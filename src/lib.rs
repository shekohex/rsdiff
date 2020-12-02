#![deny(unsafe_code)]
//! ## rsdiff(1).
//!
//! A simple implementation of [`rdiff(1)`](https://linux.die.net/man/1/rdiff).
//!
//! this not really a 1:1 `rdiff(1)` implementation, it has the same concepts like generating a
//! signature of a given buffer and then calculating the delta between the original buffer and a
//! modified one with onenly the signature.
//!
//! patching is implemented, but not ready yet!
//!
//! here is a simple examples of how it works.
//!
//! ### Examples:
//!
//! 1. Simple:
//! ```
//! use rsdiff::Operation;
//!
//! // imagine we have this simple file contains this small text.
//! let original = "i saw a red fox";
//! // now we will make a small edit to it.
//! let new = "i saw a red box";
//! // in this example we tell it to use 4 bytes as a block size.
//! let ops = rsdiff::diff_with_block_size(4, original, new);
//! for op in &ops {
//!  println!("{}", op);
//! }
//! // prints
//! // + 12..15 = "box"
//! // - 15..-3
//! assert_eq!(
//!     ops,
//!     vec![
//!         // insert the word "box" starting from 12 index.
//!         Operation::Insert { offset: 12, buffer: b"box".to_vec() },
//!         // from the index 15 remove 3 bytes (backword)
//!         // it is like if you are remving text with backspace!
//!         // or you can imagine it as how many bytes I need to skip from the buffer.
//!         Operation::Remove { offset: 15, len: 3 },
//!     ],
//! );
//!
//! ```
//!
//! 2. Insert & Remove.
//! ```
//! use rsdiff::Operation;
//!
//! let original = "hello there, do you know rust?";
//! let new = "hi, do you know about rustlang?";
//! let ops = rsdiff::diff_with_block_size(5, original, new);
//!
//! assert_eq!(
//!     ops,
//!     vec![
//!         // add "hi, do" from offset 0 to 6.
//!         Operation::Insert { offset: 0, buffer: b"hi, do".to_vec() },
//!         // from 6 skip 15 bytes ("hello there, ").
//!         Operation::Remove { offset: 6, len: 15 },
//!         // at 16 add "about rustlang?".
//!         Operation::Insert { offset: 16, buffer: b"about rustlang?".to_vec() },
//!         // remove 5 bytes ("rust?").
//!         Operation::Remove { offset: 31, len: 5 },
//!     ],
//! );
//!
//! ```
//!
//! 3. Raw API.
//! ```
//! use rsdiff::{Signature, Delta, Operation};
//!
//! // imagine we have this simple file contains this small text.
//! let original = "i saw a red fox";
//! // now we will make a small edit to it.
//! let new = "i saw a red box";
//!
//! // lets create our signature.
//! let mut signature = Signature::with_block_size(4, original);
//! // this dose not do anything itself, we need to call `calculate`.
//! signature.calculate();
//! // now we get the indexed signature.
//! let indexed_signature = signature.to_indexed();
//! // it is ready to create the `Delta`.
//! let mut delta = Delta::new(indexed_signature);
//! // we can now calculate the diff.
//! delta.diff(new);
//! let ops = delta.into_operations();
//! for op in &ops {
//!  println!("{}", op);
//! }
//! // prints
//! // + 12..15 = "box"
//! // - 15..-3
//! assert_eq!(
//!     ops,
//!     vec![
//!         // insert the word "box" starting from 12 index.
//!         Operation::Insert { offset: 12, buffer: b"box".to_vec() },
//!         // from the index 15 remove 3 bytes (backword)
//!         // it is like if you are remving text with backspace!
//!         // or you can imagine it as how many bytes I need to skip from the buffer.
//!         Operation::Remove { offset: 15, len: 3 },
//!     ],
//! );
//!
//! ```
//!

mod delta;
mod hash;
mod window;

#[doc(hidden)]
#[allow(dead_code)]
mod patch; // not ready yet.

pub use delta::{Delta, Operation};
pub use hash::{IndexedSignature, RollingHasher, Signature};

/// Convenience function to compute [`Delta`] between two buffers.
/// it will handle the creation of the [`Signature`] and the [`Delta`].
///
/// returns the total operations needed to upgrade `a` to `b`.
pub fn diff(a: impl AsRef<[u8]>, b: impl AsRef<[u8]>) -> Vec<Operation> {
    let len = std::cmp::max(a.as_ref().len(), b.as_ref().len());
    let block_size = hash::calculate_block_size(len);
    diff_with_block_size(block_size, a, b)
}

/// Same as [`diff`]. but with more control over the `block_size`.
pub fn diff_with_block_size(
    block_size: usize,
    a: impl AsRef<[u8]>,
    b: impl AsRef<[u8]>,
) -> Vec<Operation> {
    let mut signature = Signature::with_block_size(block_size, a);
    signature.calculate();
    let mut delta = Delta::new(signature.to_indexed());
    delta.diff(b).unwrap();
    delta.into_operations()
}

#[cfg(test)]
mod tests {
    use super::*;
    macro_rules! test_diff {
        (
            v1 = $v1: expr, v2 = $v2: expr, bs = $bs: expr,
            +[$(($ioffset: expr, $buf: expr)),*],
            -[$(($doffset: expr, $len: expr)),*],
        ) => {{
            let mut ops = diff_with_block_size($bs, $v1, $v2);
            ops.sort_by_key(|op| op.is_insert());
            #[allow(unused_mut)]
            let mut expected_ops: Vec<Operation> = Vec::new();
                $(
                    expected_ops.push(
                        Operation::Insert {
                            offset: $ioffset,
                            buffer: $buf.bytes().collect()
                        }
                    );
                )*
                $(
                    expected_ops.push(
                        Operation::Remove {
                            offset: $doffset,
                            len: $len
                        }
                    );
                )*
            expected_ops.sort_by_key(|op| op.is_insert());
            assert_eq!(ops, expected_ops);

        }};
    }

    fn init() {
        let _ = env_logger::builder()
            .format_timestamp(None)
            .is_test(true)
            .try_init();
    }
    #[test]
    fn test_simple() {
        init();
        test_diff!(
            v1 = "i saw a red fox",
            v2 = "i saw a red box",
            bs = 4,
            +[(12, "box")],
            -[(15, 3)],
        );
        test_diff!(
            v1 = "i saw a red fox",
            v2 = "i saw a green fox",
            bs = 8,
            +[(8, "green fox")],
            -[(17, 7)],
        );
    }

    #[test]
    fn test_inserts() {
        init();
        test_diff!(
            v1 = "my name is shady khalifa and this a test",
            v2 = "my name is shady khalifa and this a new test",
            bs = 4,
            +[(36, "new ")],
            -[],
        );

        test_diff!(
            v1 = "hello fox",
            v2 = "hello fox and friends",
            bs = 3,
            +[(9, " and friends")],
            -[],
        )
    }
    #[test]
    fn test_removes() {
        init();
        test_diff!(
            v1 = "my name is shady khalifa and this a new test",
            v2 = "my name is shady khalifa and this a test",
            bs = 4,
            +[],
            -[(36, 4)],
        );

        test_diff!(
            v1 = "hello fox and friends",
            v2 = "hello fox",
            bs = 3,
            +[],
            -[(9, 12)],
        )
    }

    #[test]
    fn test_no_changes() {
        init();
        test_diff!(
            v1 = "wow there is no updates",
            v2 = "wow there is no updates",
            bs = 4,
            +[],
            -[],
        );
    }

    #[test]
    fn test_more_changes() {
        init();
        test_diff!(
            v1 = "hello there, do you know rust?",
            v2 = "hi, do you know about rustlang?",
            bs = 5,
            +[(0, "hi, do"), (16, "about rustlang?")],
            -[(6, 15), (31, 5)],
        );
    }

    #[test]
    fn test_dynamic_block_size() {
        init();
        test_diff!(
            v1 = "hello there, do you know rust?",
            v2 = "hi, do you know about rustlang?",
            bs = hash::calculate_block_size(32),
            +[(0, "hi, do you know about rustlang?")],
            -[(31, 30)],
        );
    }
}
