use std::net::Ipv4Addr;
use crate::config::{BLOCKLIST_FILE, PERSIST_DIR};

pub fn load_persistent_ips() -> anyhow::Result<Vec<Ipv4Addr>> {
    match std::fs::read_to_string(BLOCKLIST_FILE) {
        Ok(content) => {
            let ips = content.lines()
                .filter_map(|s| s.trim().parse::<Ipv4Addr>().ok())
                .collect();
            Ok(ips)
        }
        // fixed: avoid exists() check → removes race condition
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

pub fn save_persistent_ips(ips: &[Ipv4Addr]) -> anyhow::Result<()> {
    std::fs::create_dir_all(PERSIST_DIR)?;

    let content = ips.iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    // fixed: atomic write to prevent data loss on crash
    let tmp = format!("{}.tmp", BLOCKLIST_FILE);
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, BLOCKLIST_FILE)?;

    Ok(())
}