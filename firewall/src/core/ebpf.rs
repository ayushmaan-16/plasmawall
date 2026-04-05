use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::programs::links::{FdLink, PinnedLink};
use aya::maps::Map;
use crate::config::PIN_DIR;

pub async fn attach(iface: &str) -> anyhow::Result<()> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/firewall"
    )))?;

    std::fs::create_dir_all(PIN_DIR)?;

    let program: &mut Xdp = ebpf.program_mut("firewall").unwrap().try_into()?;
    program.load()?;

    let link_id = program
        .attach(iface, XdpFlags::default())
        .context("failed to attach XDP")?;

    let link: FdLink = program.take_link(link_id)?.try_into()?;
    link.pin(format!("{}/firewall_link", PIN_DIR))?;

    ebpf.take_map("BLOCKLIST").unwrap().pin(format!("{}/BLOCKLIST", PIN_DIR))?;
    ebpf.take_map("CONFIG").unwrap().pin(format!("{}/CONFIG", PIN_DIR))?;
    ebpf.take_map("EVENTS").unwrap().pin(format!("{}/EVENTS", PIN_DIR))?;

    Ok(())
}

pub async fn detach() -> anyhow::Result<()> {
    if let Ok(link) = PinnedLink::from_pin(format!("{}/firewall_link", PIN_DIR)) {
        let fd_link: FdLink = link.into();
        drop(fd_link);
    }

    let _ = std::fs::remove_dir_all(PIN_DIR);
    Ok(())
}