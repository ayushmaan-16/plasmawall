use std::net::Ipv4Addr;
use crate::core::maps;
use crate::storage::persistence;

pub async fn run(ip: Ipv4Addr) -> anyhow::Result<()> {
    maps::insert_ip(ip)?;

    let mut ips = persistence::load_persistent_ips().unwrap_or_default();
    if !ips.contains(&ip) {
        ips.push(ip);
        persistence::save_persistent_ips(&ips)?;
        println!("[BLOCKED] {}", ip);
    } else {
        println!("[BLOCKED] {} (already exists)", ip);
    }

    Ok(())
}