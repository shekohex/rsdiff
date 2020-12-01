use std::str::Utf8Error;

use crate::{Delta, Op, OpProps};

#[derive(Debug, Clone)]
pub struct Patch<'a> {
    buffer: Vec<u8>,
    delta: Delta<'a>,
    patch_ops: Vec<Op>,
}

impl<'a> Patch<'a> {
    pub fn new(delta: Delta<'a>) -> Self {
        Self {
            buffer: Vec::new(),
            patch_ops: Vec::new(),
            delta,
        }
    }

    pub fn build(&mut self) {
        let other_buffer = self.delta.buffer();
        let ops = self
            .delta
            .operations()
            .iter()
            .filter(|op| op.is_overwrite());
        for op in ops {
            let props = op.props();
            let patch_op = Op::overwrite(self.buffer.len(), props.target, props.len);
            let start = op.source();
            let end = op.len() + start;
            self.buffer.extend(&other_buffer[start..end]);
            self.patch_ops.push(patch_op);
        }
        Delta::optimize_ops(&mut self.patch_ops);
    }

    pub fn apply(&self, original: &[u8]) -> Vec<u8> {
        let mut patched = Vec::new();
        let other_buffer = self.delta.buffer();
        patched.resize(other_buffer.len(), 0);
        let keeps = self.delta.operations().iter().filter(|op| op.is_keep());
        for op in keeps {
            Self::patch(&mut patched, original, op.props());
        }

        for op in &self.patch_ops {
            Self::patch(&mut patched, &self.buffer, op.props());
        }

        patched
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub fn buffer_utf8(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(&self.buffer)
    }

    fn patch(target: &mut [u8], soruce: &[u8], props: OpProps) {
        let tb = props.target..props.target + props.len;
        let sb = props.source..props.source + props.len;
        let ss = &soruce[sb];
        let ts = &mut target[tb];
        ts.copy_from_slice(ss);
    }
}
