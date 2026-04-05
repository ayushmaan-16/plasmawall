use crate::core::{ebpf, maps};
use crate::storage::persistence;

pub async fn run(iface: String) -> anyhow::Result<()> {
    ebpf::attach(&iface).await?;

    let ips = persistence::load_persistent_ips()?;
    for ip in ips {
        maps::insert_ip(ip)?;
    }

    println!("Firewall started on {}", iface);
    Ok(())
}