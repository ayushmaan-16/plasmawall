use crate::core::maps;
use crate::storage::persistence;

pub async fn run() -> anyhow::Result<()> {
    let ips = maps::list_ips()?;

    if ips.is_empty() {
        let saved = persistence::load_persistent_ips()?;
        if saved.is_empty() {
            println!("No blocked IPs");
        } else {
            println!("Saved IPs:");
            for ip in saved {
                println!("  {}", ip);
            }
        }
    } else {
        println!("Blocked IPs:");
        for ip in ips {
            println!("  {}", ip);
        }
    }

    Ok(())
}