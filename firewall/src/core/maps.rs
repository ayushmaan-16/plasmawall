use std::net::Ipv4Addr;
use aya::maps::{HashMap, Map, MapData};
use anyhow::Context;
use crate::config::PIN_DIR;

pub fn insert_ip(ip: Ipv4Addr) -> anyhow::Result<()> {
    if let Ok(map_data) = MapData::from_pin(format!("{}/BLOCKLIST", PIN_DIR)) {
        let map = Map::from_map_data(map_data)?;
        let mut blocklist: HashMap<MapData, u32, u8> = HashMap::try_from(map)?;

        let key = u32::from(ip).to_be();

        // fixed: earlier insert failure was ignored → now properly errors if map full
        blocklist.insert(&key, &1u8, 0)
            .context("blocklist map is full (max 1024 entries)")?;
    }
    Ok(())
}

pub fn remove_ip(ip: Ipv4Addr) -> anyhow::Result<()> {
    if let Ok(map_data) = MapData::from_pin(format!("{}/BLOCKLIST", PIN_DIR)) {
        let map = Map::from_map_data(map_data)?;
        let mut blocklist: HashMap<MapData, u32, u8> = HashMap::try_from(map)?;

        let key = u32::from(ip).to_be();

        // still ignoring if key not present, but no silent panic
        let _ = blocklist.remove(&key);
    }
    Ok(())
}

pub fn list_ips() -> anyhow::Result<Vec<Ipv4Addr>> {
    let mut result = Vec::new();

    if let Ok(map_data) = MapData::from_pin(format!("{}/BLOCKLIST", PIN_DIR)) {
        let map = Map::from_map_data(map_data)?;
        let blocklist: HashMap<MapData, u32, u8> = HashMap::try_from(map)?;

        for item in blocklist.iter() {
            if let Ok((key, _)) = item {
                result.push(Ipv4Addr::from(u32::from_be(key)));
            }
        }
    }

    Ok(result)
}

pub fn count_ips() -> anyhow::Result<usize> {
    Ok(list_ips()?.len())
}