use aya_ebpf::programs::XdpContext;

#[derive(Debug, Clone, Copy)]
pub enum ParseError {
    OutOfBounds,
    InvalidIpv4Version,
    InvalidIpv4HeaderLength
}

#[repr(C)]
pub struct EthernetHeader {
    pub destination_mac: [u8; 6],
    pub source_mac: [u8; 6],
    pub ether_type: u16, // synonym: protocol
}

#[repr(C)]
pub struct Ipv4Header {
    pub version_and_header_length: u8, 
    pub type_of_service: u8,
    pub total_length: u16,
    pub identification: u16,
    pub fragment_offset: u16,
    pub time_to_live: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_address: u32,
    pub destination_address: u32,
}

#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ParseError> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(ParseError::OutOfBounds);
    }

    Ok((start + offset) as *const T)
}