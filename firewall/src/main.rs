use anyhow::Context as _;
use aya::programs::{Xdp, XdpFlags};
use aya::programs::links::{FdLink, PinnedLink};
use aya::maps::{Array, HashMap, Map, MapData};
use aya::maps::perf::PerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use tokio::signal;
use std::net::Ipv4Addr;
use firewall_common::PacketLog;

const PIN_DIR: &str = "/sys/fs/bpf/plasmawall";
const PERSIST_DIR: &str = "/etc/plasmawall";
const BLOCKLIST_FILE: &str = "/etc/plasmawall/blocklist.txt";

#[derive(Debug, Parser)]
#[clap(name = "plasma", about = "PlasmaWall — Linux eBPF Firewall")]
struct Opt {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the firewall on a network interface
    Start {
        #[clap(short, long, default_value = "enp1s0")]
        iface: String,
    },
    /// Stop the firewall and clean up
    Stop,
    /// Show firewall status
    Status,
    /// Attach to live packet drop logs
    Log,
    /// Block an IP address
    Block {
        /// IP address to block (e.g. 8.8.8.8)
        ip: Ipv4Addr,
    },
    /// Unblock an IP address
    Unblock {
        /// IP address to unblock
        ip: Ipv4Addr,
    },
    /// List all blocked IP addresses
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the new memcg based accounting.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        eprintln!("remove limit on locked memory failed, ret is: {ret}");
    }

    match opt.command {
        Command::Start { iface } => start(iface).await,
        Command::Stop => stop().await,
        Command::Status => status().await,
        Command::Log => log_events().await,
        Command::Block { ip } => block_ip(ip).await,
        Command::Unblock { ip } => unblock_ip(ip).await,
        Command::List => list_blocked().await,
    }
}

// ─── Start ──────────────────────────────────────────────

async fn start(iface: String) -> anyhow::Result<()> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/firewall"
    )))?;

    std::fs::create_dir_all(PIN_DIR)?;

    let program: &mut Xdp = ebpf.program_mut("firewall").unwrap().try_into()?;
    program.load()?;
    let link_id = program
        .attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program")?;

    let owned_link: FdLink = program.take_link(link_id)?.try_into()?;
    owned_link.pin(format!("{}/firewall_link", PIN_DIR))?;

    let blocklist = ebpf.take_map("BLOCKLIST").unwrap();
    blocklist.pin(format!("{}/BLOCKLIST", PIN_DIR))?;

    let config = ebpf.take_map("CONFIG").unwrap();
    config.pin(format!("{}/CONFIG", PIN_DIR))?;

    let events = ebpf.take_map("EVENTS").unwrap();
    events.pin(format!("{}/EVENTS", PIN_DIR))?;

    // State Rehydration: Restore blocked IPs from persistence
    if let Ok(ips) = load_persistent_ips() {
        if !ips.is_empty() {
            let map_data = MapData::from_pin(format!("{}/BLOCKLIST", PIN_DIR))?;
            let map = Map::from_map_data(map_data)?;
            let mut blocklist: HashMap<MapData, u32, u8> = HashMap::try_from(map)?;
            
            for ip in &ips {
                let key = u32::from(*ip).to_be();
                if let Err(e) = blocklist.insert(&key, &1u8, 0) {
                    eprintln!("Failed to rehydrate IP {}: {}", ip, e);
                }
            }
            println!("  Restored {} blocked IPs from persistence", ips.len());
        }
    }

    println!("[SUCCESS] Firewall ACTIVATED on {}", iface);
    Ok(())
}

// ─── Stop ───────────────────────────────────────────────

async fn stop() -> anyhow::Result<()> {
    match PinnedLink::from_pin(format!("{}/firewall_link", PIN_DIR)) {
        Ok(link) => {
            let fd_link: FdLink = link.into();
            drop(fd_link);
        }
        Err(_) => {
            println!("Could not find pinned link. Maybe already detached?");
        }
    }

    if let Err(e) = std::fs::remove_dir_all(PIN_DIR) {
        println!("Cleanup info: Could not remove directory at {}: {}", PIN_DIR, e);
    }

    println!("[SUCCESS] Firewall detached and cleaned up.");
    Ok(())
}

// ─── Status ─────────────────────────────────────────────

async fn status() -> anyhow::Result<()> {
    let link_path = format!("{}/firewall_link", PIN_DIR);

    if !std::path::Path::new(&link_path).exists() {
        println!("Firewall is INACTIVE");
        return Ok(());
    }

    println!("Firewall is ACTIVE");

    // Check global block config
    if let Ok(map_data) = MapData::from_pin(format!("{}/CONFIG", PIN_DIR)) {
        if let Ok(map) = Map::from_map_data(map_data) {
            if let Ok(config) = Array::<MapData, u8>::try_from(map) {
                if let Ok(val) = config.get(&0, 0) {
                    if val == 1 {
                        println!("  Global block:  ENABLED (all traffic dropped)");
                    } else {
                        println!("  Global block:  disabled");
                    }
                }
            }
        }
    }

    // Count blocked IPs
    if let Ok(map_data) = MapData::from_pin(format!("{}/BLOCKLIST", PIN_DIR)) {
        if let Ok(map) = Map::from_map_data(map_data) {
            if let Ok(blocklist) = HashMap::<MapData, u32, u8>::try_from(map) {
                let count = blocklist.iter().filter(|r| r.is_ok()).count();
                println!("  Blocked IPs:   {}", count);
            }
        }
    }

    Ok(())
}

// ─── Block / Unblock / List ─────────────────────────────

async fn block_ip(ip: Ipv4Addr) -> anyhow::Result<()> {
    // Try to inject into the live kernel map if active
    if let Ok(map_data) = MapData::from_pin(format!("{}/BLOCKLIST", PIN_DIR)) {
        if let Ok(map) = Map::from_map_data(map_data) {
            if let Ok(mut blocklist) = HashMap::<MapData, u32, u8>::try_from(map) {
                let key = u32::from(ip).to_be();
                let _ = blocklist.insert(&key, &1u8, 0);
            }
        }
    }

    // Always persist to the saved file
    let mut ips = load_persistent_ips().unwrap_or_default();
    if !ips.contains(&ip) {
        ips.push(ip);
        save_persistent_ips(&ips)?;
        println!("[BLOCKED] {} (Saved permanently)", ip);
    } else {
        println!("[BLOCKED] {} (Already in list)", ip);
    }

    Ok(())
}

async fn unblock_ip(ip: Ipv4Addr) -> anyhow::Result<()> {
    // Try to remove from the live kernel map if active
    if let Ok(map_data) = MapData::from_pin(format!("{}/BLOCKLIST", PIN_DIR)) {
        if let Ok(map) = Map::from_map_data(map_data) {
            if let Ok(mut blocklist) = HashMap::<MapData, u32, u8>::try_from(map) {
                let key = u32::from(ip).to_be();
                let _ = blocklist.remove(&key);
            }
        }
    }

    // Always update persistent file
    let mut ips = load_persistent_ips().unwrap_or_default();
    if ips.contains(&ip) {
        ips.retain(|x| x != &ip);
        save_persistent_ips(&ips)?;
        println!("[UNBLOCKED] {} (Removed permanently)", ip);
    } else {
        println!("[UNBLOCKED] {} (Not found in list)", ip);
    }

    Ok(())
}

async fn list_blocked() -> anyhow::Result<()> {
    match MapData::from_pin(format!("{}/BLOCKLIST", PIN_DIR)) {
        Ok(map_data) => {
            // Firewall is ACTIVE - read from real-time kernel memory
            let map = Map::from_map_data(map_data)?;
            let blocklist: HashMap<MapData, u32, u8> = HashMap::try_from(map)?;

            let mut count = 0;
            println!("Blocked IPs (Active in Kernel):");
            for item in blocklist.iter() {
                if let Ok((key, _)) = item {
                    let ip = Ipv4Addr::from(u32::from_be(key));
                    println!("  - {}", ip);
                    count += 1;
                }
            }

            if count == 0 {
                println!("  (none)");
            }

            println!("\nTotal: {} active blocked", count);
        }
        Err(_) => {
            // Firewall is INACTIVE - read directly from persistent disk state
            let ips = load_persistent_ips().unwrap_or_default();
            
            if ips.is_empty() {
                println!("Firewall is INACTIVE. Saved Blocklist is empty.");
            } else {
                println!("Firewall is INACTIVE. Saved Blocked IPs:");
                for ip in &ips {
                    println!("  - {}", ip);
                }
                println!("\nTotal: {} saved (will automatically activate on 'start')", ips.len());
            }
        }
    }

    Ok(())
}

// ─── Live Logs ──────────────────────────────────────────

async fn log_events() -> anyhow::Result<()> {
    let map_data = MapData::from_pin(format!("{}/EVENTS", PIN_DIR))
        .context("Firewall is not running. Start it first with: sudo plasma start")?;
    let map = Map::from_map_data(map_data)?;
    let mut perf_array: PerfEventArray<MapData> = PerfEventArray::try_from(map)?;

    for cpu_id in online_cpus().map_err(|(_, e)| e)? {
        let buf = perf_array.open(cpu_id, None)?;
        let mut async_fd = tokio::io::unix::AsyncFd::new(buf)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();
            loop {
                // Wait for the FD to become readable via epoll
                let mut guard = async_fd.readable_mut().await.unwrap();
                let buf = guard.get_inner_mut();

                if let Ok(events) = buf.read_events(&mut buffers) {
                    for i in 0..events.read {
                        let ptr = buffers[i].as_ptr() as *const PacketLog;
                        let log_entry = unsafe { ptr.read_unaligned() };

                        let src = Ipv4Addr::from(u32::from_be(log_entry.source_ip));
                        let dst = Ipv4Addr::from(u32::from_be(log_entry.destination_ip));

                        let action_str = match log_entry.action {
                            firewall_common::ACTION_DROP => "DROP",
                            firewall_common::ACTION_PASS => "PASS",
                            _ => "UNKNOWN",
                        };

                        let reason_str = match log_entry.reason {
                            firewall_common::REASON_GLOBAL_DROP => "Global Drop",
                            firewall_common::REASON_BLOCKLIST => "Blocklist",
                            _ => "Unknown",
                        };

                        println!(
                            "[{}] Traffic from {} to {} stopped. (Reason: {})",
                            action_str, src, dst, reason_str
                        );
                    }
                }
                guard.clear_ready();
            }
        });
    }

    println!("[ATTACHED TO LIVE LOGS] Waiting for packets...");
    println!("Press Ctrl-C to exit viewer. The firewall will continue running in the background.");
    let ctrl_c = signal::ctrl_c();
    ctrl_c.await?;
    println!("Detached log viewer.");
    Ok(())
}

// ─── Persistence Helpers ──────────────────────────────

fn load_persistent_ips() -> anyhow::Result<Vec<Ipv4Addr>> {
    if !std::path::Path::new(BLOCKLIST_FILE).exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(BLOCKLIST_FILE)?;
    let ips = content.lines()
        .filter_map(|s| s.trim().parse::<Ipv4Addr>().ok())
        .collect();
    Ok(ips)
}

fn save_persistent_ips(ips: &[Ipv4Addr]) -> anyhow::Result<()> {
    std::fs::create_dir_all(PERSIST_DIR)?;
    let content = ips.iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(BLOCKLIST_FILE, content)?;
    Ok(())
}
