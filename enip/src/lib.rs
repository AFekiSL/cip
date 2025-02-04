// #![no_std]

mod common;
pub mod cpf;
pub mod encapsulation;
#[cfg(feature = "tcp-client")]
pub mod tcp;
#[cfg(feature = "udp-client")]
pub mod udp;
extern crate alloc;
