#![no_std]
#![no_main]

mod packet;
mod engine;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, Array, PerfEventArray},
    programs::XdpContext,
};

use firewall_common::PacketLog;

#[map]
static BLOCKLIST: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(1024, 0);

#[map]
static CONFIG: Array<u8> = Array::<u8>::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

#[xdp]
pub fn firewall(context: XdpContext) -> u32 {
    match engine::evaluate_packet(&context, &BLOCKLIST, &CONFIG, &EVENTS) {
        Ok(result) => result,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_panic_information: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";