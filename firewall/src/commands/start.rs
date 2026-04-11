use crate::core::{ebpf, maps};
use crate::storage::persistence;

pub async fn run(iface: String) -> anyhow::Result<()> {

    // attach first so maps exist
    ebpf::attach(&iface).await?;

    // then rehydrate blocklist into kernel
    let ips = persistence::load_persistent_ips()?;
    for ip in ips {
        maps::insert_ip(ip)?;
    }

    println!("Firewall started on {}", iface);
    Ok(())
}