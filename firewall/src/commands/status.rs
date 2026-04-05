use crate::config::PIN_DIR;
use crate::core::maps;

pub async fn run() -> anyhow::Result<()> {
    let link_path = format!("{}/firewall_link", PIN_DIR);

    if !std::path::Path::new(&link_path).exists() {
        println!("Firewall is INACTIVE");
        return Ok(());
    }

    println!("Firewall is ACTIVE");
    println!("Blocked IPs: {}", maps::count_ips()?);

    Ok(())
}