use num_bigint::*;

#[derive(Clone, Debug)]
pub(crate) struct Constant {
    pub(crate) value: Vec<ConstantValue>,
}

#[derive(Clone, Debug)]
pub enum ConstantValue {
    Cell([u8; 32]),
    Signed(BigInt, usize),
    Unsigned(BigUint, usize),
    ByteArray(Vec<u8>),
}

impl ConstantValue {
    pub fn serialize(self) -> [u8; 32] {
        match self {
            ConstantValue::Cell(res) => res,
            _ => todo!(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            ConstantValue::Cell(res) => res.iter().all(|el| *el == 0),
            _ => todo!(),
        }
    }
}
