#![no_std]

#[repr(C)] //forces c compiler action , otherwise rust might rearrange fileds for performance which will cause field mismatch
#[derive(Clone, Copy)]
// SAFETY: All fields MUST be initialized before sending to user space.
// Uninitialized bytes will leak kernel memory via Pod.
pub struct PacketLog {
    pub source_ip: u32,
    pub destination_ip: u32,
    pub action: u8,
    pub reason: u8,
    pub _padding: u16,
}

impl PacketLog {
    pub fn new(src: u32, dst: u32, action: u8, reason: u8) -> Self {
        Self {
            source_ip: src,
            destination_ip: dst,
            action,
            reason,
            _padding: 0,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}



//for user space safety match actions
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Action {
    Pass = 0,
    Drop = 1,
}

impl Action {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Action::Pass),
            1 => Some(Action::Drop),
            _ => None,
        }
    }
}




#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Reason {
    Unknown = 0,
    GlobalDrop = 1,
    Blocklist = 2,
}

impl Reason {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Reason::Unknown),
            1 => Some(Reason::GlobalDrop),
            2 => Some(Reason::Blocklist),
            _ => None,
        }
    }
}


pub const ACTION_PASS: u8 = Action::Pass as u8;
pub const ACTION_DROP: u8 = Action::Drop as u8;

pub const REASON_UNKNOWN: u8 = Reason::Unknown as u8;
pub const REASON_GLOBAL_DROP: u8 = Reason::GlobalDrop as u8;
pub const REASON_BLOCKLIST: u8 = Reason::Blocklist as u8;