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
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let mut guard = async_fd.readable_mut().await.unwrap();
                let buf = guard.get_inner_mut();

                if let Ok(events) = buf.read_events(&mut buffers) {
                    for i in 0..events.read {
                        let ptr = buffers[i].as_ptr() as *const PacketLog;
                        let log = unsafe { ptr.read_unaligned() };

                        let src = Ipv4Addr::from(u32::from_be(log.source_ip));
                        let dst = Ipv4Addr::from(u32::from_be(log.destination_ip));

                        println!(
                            "[{}] {} -> {} (reason: {})",
                            log.action, src, dst, log.reason
                        );
                    }
                }

                guard.clear_ready();
            }
        });
    }

    signal::ctrl_c().await?;
    Ok(())
}