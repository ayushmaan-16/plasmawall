# PlasmaWall — Linux eBPF Firewall

PlasmaWall is a high-performance, stateless Linux firewall built using eBPF and XDP. It provides a fast and efficient way to drop or allow network packets directly at the network interface level.

## Features
- **XDP-Based Dropping**: Extremely low overhead by dropping packets as soon as they hit the driver.
- **Persistent State**: Blocked IPs and rules survive system reboots and firewall restarts.
- **Offline Mode**: Manage your blocklist even when the firewall is inactive.
- **Live Logging**: Real-time event streaming of dropped packets per CPU core.

## Prerequisites
- **OS**: Linux (Fedora/Ubuntu/Debian recommended).
- **Tooling**: `clang`, `llvm`, `libelf-dev` (or `elfutils-libelf-devel`), and `bpf-linker`.
- **Rust**: Nightly toolchain is automatically handled via `rust-toolchain.toml`.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ayushmaan-16/plasmawall.git
   cd plasmawall/firewall
   ```

2. **Build the project**:
   ```bash
   cargo build --release
   ```

3. **Install the CLI globally**:
   ```bash
   sudo cp ../target/release/firewall /usr/local/bin/plasma
   ```

## Usage Guide

To use the firewall correctly, follow this standard workflow:

### 1. View Current Status
Check if the firewall is active or inactive.
```bash
sudo plasma status
```

### 2. Manage the Blocklist (Offline or Online)
You can add or remove IPs at any time. If the firewall is stopped, the changes are saved to `/etc/plasmawall/blocklist.txt` and will be loaded when you start the firewall.
```bash
# Block an IP
sudo plasma block 8.8.8.8

# List currently blocked IPs
sudo plasma list

# Unblock an IP
sudo plasma unblock 8.8.8.8
```

### 3. Start the Firewall
Activate the firewall on a specific network interface (e.g., `enp1s0`, `eth0`).
```bash
sudo plasma start --iface enp1s0
```

### 4. Monitor Live Logs
In a separate terminal, watch packet drops as they happen in real-time.
```bash
sudo plasma log
```

### 5. Stop the Firewall
Gracefully detach the XDP program and clean up kernel resources.
```bash
sudo plasma stop
```

---

## Roadmap: Stateless Ruleset
We are currently moving towards a more granular **Stateless Ruleset** system. This version will support:
- Port-based filtering (TCP/UDP/ICMP).
- Comprehensive rule matching (Source IP + Destination IP + Port + Protocol).
- Granular rule management via the `plasma` CLI.