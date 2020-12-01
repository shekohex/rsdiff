mod delta;
mod hash;
mod patch;

pub use delta::{Delta, Op, OpProps};
pub use hash::{IndexedSignature, Signature};
pub use patch::Patch;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_one() {
        let original = "shady khalifa is my name and this a test";
        let new = original.to_string().replace("test", "testing");
        let mut signature = Signature::with_block_size(128, original.as_bytes());
        signature.calculate();
        let mut delta = Delta::new(signature.to_indexed(), new.as_bytes());
        delta.calculate();
        println!("{:#?}", delta.operations());
        let mut patch = Patch::new(delta);
        patch.build();
        println!("Patch: {:?}", patch.buffer_utf8());
        let result = patch.apply(original.as_bytes());
        println!("Final: {:?}", std::str::from_utf8(&result));
    }
}
