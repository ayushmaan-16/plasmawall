use std::net::Ipv4Addr;
use crate::config::{BLOCKLIST_FILE, PERSIST_DIR};


pub fn load_persistent_ips() -> anyhow::Result<Vec<Ipv4Addr>> {
    if !std::path::Path::new(BLOCKLIST_FILE).exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(BLOCKLIST_FILE)?;
    let ips = content.lines()
        .filter_map(|s| s.trim().parse::<Ipv4Addr>().ok())
        .collect();
    Ok(ips)
}

pub fn save_persistent_ips(ips: &[Ipv4Addr]) -> anyhow::Result<()> {
    std::fs::create_dir_all(PERSIST_DIR)?;
    let content = ips.iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(BLOCKLIST_FILE, content)?;
    Ok(())
}