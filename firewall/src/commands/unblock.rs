use std::net::Ipv4Addr;
use crate::core::maps;
use crate::storage::persistence;

pub async fn run(ip: Ipv4Addr) -> anyhow::Result<()> {
    

    let mut ips = persistence::load_persistent_ips().unwrap_or_default();
    ips.retain(|x| x != &ip);
    persistence::save_persistent_ips(&ips)?;
    maps::remove_ip(ip)?;
    //remove from disk then update map

    println!("[UNBLOCKED] {}", ip);
    Ok(())
}