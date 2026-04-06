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
    pub ether_type: u16, // network byte order (big endian)
}

// converts big endian network to host format so engine doesnt mess it up
impl EthernetHeader {
    pub fn ether_type_host(&self) -> u16 {
        u16::from_be(self.ether_type)
    }
}

#[repr(C)]
pub struct Ipv4Header {
    pub version_and_header_length: u8, 
    pub type_of_service: u8,
    pub total_length: u16,
    pub identification: u16,
    pub fragment_offset: u16, // contains flags + offset in network byte order
    pub time_to_live: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_address: u32,      // network byte order
    pub destination_address: u32, // network byte order
}

// convert ip addresses to host format so comparisons/logging are correct
impl Ipv4Header {
    // ONLY for logging / user-space style usage
    // DO NOT use for map lookup or kernel comparisons (breaks endian match)
    pub fn source_address_host_log(&self) -> u32 {
        u32::from_be(self.source_address)
    }
    //not for kernel this is not in correct order
    pub fn destination_address_host_log(&self) -> u32 {
        u32::from_be(self.destination_address)
    }

    // check fragmentation flags and offset (prevents firewall bypass via fragments)
    pub fn is_fragmented(&self) -> bool {
        let frag = u16::from_be(self.fragment_offset);
        (frag & 0x2000) != 0 || (frag & 0x1FFF) != 0
    }
}

#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ParseError> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    // prevent overflow + ensure bounds so verifier accepts program
    let end_check = start
        .checked_add(offset)
        .and_then(|v| v.checked_add(len))
        .ok_or(ParseError::OutOfBounds)?;

    if end_check > end {
        return Err(ParseError::OutOfBounds);
    }

    Ok((start + offset) as *const T)
}