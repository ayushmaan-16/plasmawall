use crate::core::maps;
use crate::storage::persistence;
use crate::config::PIN_DIR;

pub async fn run() -> anyhow::Result<()> {

    // check if firewall is active by checking if map is pinned
    let map_path = format!("{}/BLOCKLIST", PIN_DIR);
    let firewall_active = std::path::Path::new(&map_path).exists();

    if firewall_active {
        let ips = maps::list_ips()?;

        if ips.is_empty() {
            println!("Firewall is active, no IPs blocked");
        } else {
            println!("Blocked IPs:");
            for ip in ips {
                println!("  {}", ip);
            }
        }
    } else {
        // fallback to saved file only if firewall not running
        let saved = persistence::load_persistent_ips()?;

        if saved.is_empty() {
            println!("No blocked IPs");
        } else {
            println!("Saved IPs:");
            for ip in saved {
                println!("  {}", ip);
            }
        }
    }

    Ok(())
}