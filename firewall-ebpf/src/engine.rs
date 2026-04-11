use aya_ebpf::bindings::xdp_action;
use aya_ebpf::programs::XdpContext;
use aya_ebpf::maps::{HashMap, Array, PerfEventArray};

use crate::packet::{EthernetHeader, Ipv4Header, ptr_at, ParseError};

use firewall_common::{PacketLog, ACTION_DROP, REASON_GLOBAL_DROP, REASON_BLOCKLIST};

// engine takes the context and a reference of the blocklist map
pub fn evaluate_packet(
    context: &XdpContext, 
    blocklist: &HashMap<u32, u8>, 
    config: &Array<u8>, 
    events: &PerfEventArray<PacketLog>
) -> Result<u32, ParseError> {
    // read Ethernet Header
    let ethernet_header: *const EthernetHeader = unsafe { ptr_at(context, 0)? };
    
    // get Ethernet Protocol (use helper so engine doesnt deal with endian)
    let ethernet_protocol = unsafe { (*ethernet_header).ether_type_host() };

    // Check if IPv4 packet (0x0800)
    if ethernet_protocol != 0x0800 {return Ok(xdp_action::XDP_PASS);}

    // read IPv4 Header
    let ethernet_header_length = core::mem::size_of::<EthernetHeader>();
    let ipv4_header: *const Ipv4Header = unsafe { ptr_at(context, ethernet_header_length)?};

    // ipv4 version & length verification
    let version_ihl = unsafe { (*ipv4_header).version_and_header_length };
    
    let version = version_ihl >> 4; // top 4 bits are version
    if version != 4 {return Err(ParseError::InvalidIpv4Version);}

    let ihl = version_ihl & 0x0F; // bottom 4 bits (& mask)
    if ihl < 5 {return Err(ParseError::InvalidIpv4HeaderLength);}

    // drop fragmented packets (prevents bypass when later doing port filtering)
    if unsafe { (*ipv4_header).is_fragmented() } {
        return Ok(xdp_action::XDP_DROP);
    }
    
    // get Source and Destination in host format (network is big endian so convert)
   let source_ip_address = unsafe { (*ipv4_header).source_address };
   let destination_ip_address = unsafe { (*ipv4_header).destination_address };   

    // Global drop-all packets config (config = 0)
    if let Some(&global_block) =  config.get(0) {
        if global_block == 1 {

            let log = PacketLog::new(
                source_ip_address,
                destination_ip_address,
                ACTION_DROP,
                REASON_GLOBAL_DROP,
            );

            // use current cpu only 
            events.output(context, &log, 0);

            return Ok(xdp_action::XDP_DROP);
        }
    }

    // Match in the blocklist (already in host format so consistent)
    if let Some(&action) = unsafe { blocklist.get(&source_ip_address) } {
        if action == 1 {
            
            let log = PacketLog::new(
                source_ip_address,
                destination_ip_address,
                ACTION_DROP,
                REASON_BLOCKLIST,
            );

            events.output(context, &log, 0);
            
            return Ok(xdp_action::XDP_DROP);
        }
    }

    Ok(xdp_action::XDP_PASS)
}