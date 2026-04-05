#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub source_ip: u32,
    pub destination_ip: u32,
    pub action: u8,
    pub reason: u8,
    pub _padding: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}

pub const ACTION_PASS: u8 = 0;
pub const ACTION_DROP: u8 = 1;

pub const REASON_UNKNOWN: u8 = 0;
pub const REASON_GLOBAL_DROP: u8 = 1;
pub const REASON_BLOCKLIST: u8 = 2;