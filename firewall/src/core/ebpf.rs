use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::programs::links::{FdLink, PinnedLink};
use crate::config::PIN_DIR;

pub async fn attach(iface: &str) -> anyhow::Result<()> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/firewall"
    )))?;

    std::fs::create_dir_all(PIN_DIR)?;

    // set memlock to infinity or older kernels will fail loading ebpf silently
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    // load program in its own scope so mutable borrow ends before map operations
    {
        let program: &mut Xdp = ebpf
            .program_mut("firewall")
            .context("XDP program 'firewall' not found")?
            .try_into()?;

        program.load()?;
    } // borrow ends here so ebpf can be used again

    // pin maps first so firewall doesnt run without maps if anything fails later
    ebpf.take_map("BLOCKLIST")
        .context("BLOCKLIST map missing")?
        .pin(format!("{}/BLOCKLIST", PIN_DIR))?;

    ebpf.take_map("CONFIG")
        .context("CONFIG map missing")?
        .pin(format!("{}/CONFIG", PIN_DIR))?;

    ebpf.take_map("EVENTS")
        .context("EVENTS map missing")?
        .pin(format!("{}/EVENTS", PIN_DIR))?;

    // borrow program again now that previous borrow is dropped
    let program: &mut Xdp = ebpf
        .program_mut("firewall")
        .context("XDP program 'firewall' not found")?
        .try_into()?;

    // attach after maps are pinned so no partial state
    let link_id = program
        .attach(iface, XdpFlags::default())
        .context("failed to attach XDP")?;

    let link: FdLink = program.take_link(link_id)?.try_into()?;

    // pin link last so everything above must succeed first
    link.pin(format!("{}/firewall_link", PIN_DIR))?;

    Ok(())
}

pub async fn detach() -> anyhow::Result<()> {
    // safely detach if exists (no panic if already stopped)
    if let Ok(link) = PinnedLink::from_pin(format!("{}/firewall_link", PIN_DIR)) {
        let fd_link: FdLink = link.into();
        drop(fd_link); // dropping detaches program
    }

    // cleanup
    if let Err(e) = std::fs::remove_dir_all(PIN_DIR) {
        eprintln!("failed to remove pin dir: {}", e);
    }

    Ok(())
}