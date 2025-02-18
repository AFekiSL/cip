use alloc::vec::Vec;
use cip::cip::CipResult;

pub trait Serializable {
    fn deserialize(input: &[u8]) -> CipResult<(&[u8], Self)>
    where
        Self: Sized;
    fn serialize(&self) -> Vec<u8>;
}
