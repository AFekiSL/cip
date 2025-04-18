use alloc::vec::Vec;
use talc::*;

use crate::cip::{CipError, CipResult};

static mut ARENA: [u8; 10000000] = [0; 10000000];

#[global_allocator]
static ALLOCATOR: Talck<spin::Mutex<()>, ClaimOnOom> = Talc::new(unsafe {
    // if we're in a hosted environment, the Rust runtime may allocate before
    // main() is called, so we need to initialize the arena automatically
    ClaimOnOom::new(Span::from_const_array(core::ptr::addr_of!(ARENA)))
})
.lock();

pub trait Serializable {
    fn deserialize(input: &[u8]) -> CipResult<(&[u8], Self)>
    where
        Self: Sized;
    fn serialize(&self) -> CipResult<Vec<u8>>;
}

pub struct ItemCountListPair<T>
where
    T: Serializable,
{
    pub length: u16,
    pub data: Vec<T>,
}

impl<T> Serializable for ItemCountListPair<T>
where
    T: Serializable,
{
    fn deserialize(_input: &[u8]) -> CipResult<(&[u8], ItemCountListPair<T>)> {
        return Err(CipError::Other(
            "Unable to deserialize ItemCountListPair".to_string(),
        ));
    }

    fn serialize(&self) -> CipResult<Vec<u8>> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.length.to_le_bytes());

        for n in &self.data {
            vec.extend(&n.serialize()?)
        }

        return Ok(vec);
    }
}
