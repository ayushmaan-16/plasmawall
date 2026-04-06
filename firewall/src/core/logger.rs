use aya::maps::{Map, MapData};
use aya::maps::perf::PerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use tokio::signal;
use std::net::Ipv4Addr;
use firewall_common::PacketLog;
use crate::config::PIN_DIR;

pub async fn run() -> anyhow::Result<()> {
    let map_data = MapData::from_pin(format!("{}/EVENTS", PIN_DIR))?;
    let map = Map::from_map_data(map_data)?;
    let mut perf_array: PerfEventArray<MapData> = PerfEventArray::try_from(map)?;

    for cpu in online_cpus().map_err(|(_, e)| e)? {
        let buf = perf_array.open(cpu, None)?;
        let mut async_fd = tokio::io::unix::AsyncFd::new(buf)?;

        tokio::spawn(async move {
            // fixed: earlier allocated 1024 bytes for ~10 byte struct (100x waste)
            // now using exact struct size + small extra for perf event metadata
            let size = core::mem::size_of::<PacketLog>() + 64;

            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(size))
                .collect::<Vec<_>>();

            loop {
                // fixed: removed unwrap so logging thread doesnt panic and die silently
                let mut guard = match async_fd.readable_mut().await {
                    Ok(g) => g,
                    Err(_) => continue,
                };

                let buf = guard.get_inner_mut();

                if let Ok(events) = buf.read_events(&mut buffers) {

                    // fixed: cleaner iteration instead of indexing
                    for buf in buffers.iter().take(events.read) {

                        // fixed: proper bounds check on actual buffer (not perf handle)
                        // prevents out-of-bounds read when casting to PacketLog
                        if buf.len() < core::mem::size_of::<PacketLog>() {
                            continue;
                        }

                        let ptr = buf.as_ptr() as *const PacketLog;

                        // read_unaligned required because perf buffer is not guaranteed aligned
                        let log = unsafe { ptr.read_unaligned() };

                        // convert back from big endian (kernel wrote in network order)
                        let src = Ipv4Addr::from(u32::from_be(log.source_ip));
                        let dst = Ipv4Addr::from(u32::from_be(log.destination_ip));

                        // fixed: earlier printed raw numbers (0,1,2) which is useless
                        // now mapping to readable values
                        let action_str = match log.action {
                            0 => "PASS",
                            1 => "DROP",
                            _ => "UNKNOWN",
                        };

                        let reason_str = match log.reason {
                            0 => "UNKNOWN",
                            1 => "GLOBAL_DROP",
                            2 => "BLOCKLIST",
                            _ => "INVALID",
                        };

                        println!(
                            "[{}] {} -> {} (reason: {})",
                            action_str, src, dst, reason_str
                        );
                    }
                }

                guard.clear_ready();
            }
        });
    }

    // waits for ctrl+c (tasks will stop when process exits)
    signal::ctrl_c().await?;
    Ok(())
}