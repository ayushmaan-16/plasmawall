use std::net::Ipv4Addr;
use crate::core::maps;
use crate::storage::persistence;

pub async fn run(ip: Ipv4Addr) -> anyhow::Result<()> {
    

    let mut ips = persistence::load_persistent_ips()?;
    //dont ignore if file read fails
    if !ips.contains(&ip) {
        ips.push(ip);
        persistence::save_persistent_ips(&ips)?;
        println!("[BLOCKED] {}", ip);
    } else {
        println!("[BLOCKED] {} (already exists)", ip);
    }
    maps::insert_ip(ip)?;
    //save to disk tthen update map

    Ok(())
}