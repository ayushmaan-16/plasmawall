use crate::core::ebpf;

pub async fn run() -> anyhow::Result<()> {
    ebpf::detach().await?;
    println!("Firewall stopped");
    Ok(())
}