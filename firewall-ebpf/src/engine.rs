use aya_ebpf::bindings::xdp_action;
use aya_ebpf::programs::XdpContext;
use aya_ebpf::maps::{HashMap, Array, PerfEventArray};
use aya_log_ebpf::info;

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
    
    // get Ethernet Protocol
    let ethernet_protocol = u16::from_be(unsafe { (*ethernet_header).ether_type });

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
    
    // get Source address and dest address
    let source_ip_address = unsafe { (*ipv4_header).source_address };
    let destination_ip_address = unsafe { (*ipv4_header).destination_address };    

    // Global drop-all packets config (config = 0)
    if let Some(&global_block) =  config.get(0) {
        if global_block == 1 {

            let log = PacketLog {
                source_ip: source_ip_address,
                destination_ip: destination_ip_address,
                action: ACTION_DROP,
                reason: REASON_GLOBAL_DROP,
                _padding: 0,
            };

            events.output(context, &log, 0);

            // TODO: remove info!() when event catching in firewall crate is implemented
            info!(context, "Dropped: Global DROP ALL is active!");
            return Ok(xdp_action::XDP_DROP);
        }
    }

    
    

    // Match in the blocklist
    if let Some(&action) = unsafe { blocklist.get(&source_ip_address) } {
        if action == 1 {
            
            let log = PacketLog {
                source_ip: source_ip_address,
                destination_ip: destination_ip_address,
                action: ACTION_DROP,
                reason: REASON_BLOCKLIST,
                _padding: 0,
            };

            events.output(context, &log, 0);
            
            // TODO: remove info!() when event catching in firewall crate is implemented
            info!(context, "Dropped packet from blocked IP!");
            return Ok(xdp_action::XDP_DROP);
        }
    }

    
    
    info!(context, "Packet passed");
    Ok(xdp_action::XDP_PASS)
}