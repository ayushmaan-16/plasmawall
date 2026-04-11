<div align="center">

```
██████╗ ██╗      █████╗ ███████╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██╗     ██╗
██╔══██╗██║     ██╔══██╗██╔════╝████╗ ████║██╔══██╗██║    ██║██╔══██╗██║     ██║
██████╔╝██║     ███████║███████╗██╔████╔██║███████║██║ █╗ ██║███████║██║     ██║
██╔═══╝ ██║     ██╔══██║╚════██║██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██║     ██║
     ██║     ███████╗██║  ██║███████║██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║███████╗███████╗
     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝
```

**A high-performance Linux firewall built with eBPF and XDP — written in Rust.**

![Rust](https://img.shields.io/badge/Rust-nightly-orange?logo=rust)
![eBPF](https://img.shields.io/badge/eBPF-XDP-blue)
![Linux](https://img.shields.io/badge/Linux-5.15%2B-yellow?logo=linux)
![License](https://img.shields.io/badge/License-MIT%20%7C%20Apache--2.0-green)

</div>

---

## What is PlasmaWall?

PlasmaWall intercepts network packets at the **earliest possible point** — the moment they hit your network card — using Linux's **XDP (eXpress Data Path)** hook. Before the kernel even begins processing a packet, PlasmaWall has already decided: let it through, or throw it away.

This is fundamentally different from tools like `iptables`, which operate deeper in the networking stack after the kernel has already done significant work. XDP runs inside the **kernel driver layer**, which means:

- Near line-rate packet dropping with minimal CPU overhead
- No userspace context switches per packet
- Blocked traffic never reaches your applications

The firewall is managed through the `plasma` CLI — a userspace tool that lets you block IPs, view live packet logs, and start or stop the firewall, all without touching a config file.

---

## Architecture

PlasmaWall is split into two programs that communicate through **eBPF Maps** — shared memory structures in the kernel:

```
┌──────────────────────────────────────────────────┐
│                  USER SPACE                       │
│                                                   │
│   plasma  (the CLI you interact with)             │
│   ├── plasma start  → loads eBPF into kernel      │
│   ├── plasma block  → writes IP into kernel map   │
│   ├── plasma log    → reads dropped-packet events │
│   └── plasma stop   → detaches & cleans up        │
└─────────────────────┬────────────────────────────┘
                      │  eBPF Maps (shared memory)
        ┌─────────────┼──────────────┐
        │             │              │
    BLOCKLIST       CONFIG         EVENTS
  (IP→drop rules) (global flags) (packet logs)
        │             │              │
┌───────▼─────────────▼──────────────▼────────────┐
│                 KERNEL SPACE                      │
│                                                   │
│   firewall  (eBPF XDP program)                    │
│   Runs for every packet, before the OS sees it.   │
│   1. Is it IPv4? No → PASS                        │
│   2. Is it fragmented? Yes → DROP                 │
│   3. Is global drop on? Yes → DROP + LOG          │
│   4. Is source IP in BLOCKLIST? Yes → DROP + LOG  │
│   5. Otherwise → PASS                             │
└─────────────────────┬────────────────────────────┘
                      │ attached to
┌─────────────────────▼────────────────────────────┐
│           NETWORK INTERFACE (e.g. eth0)           │
│    Packet arrives here from the physical NIC      │
└──────────────────────────────────────────────────┘
```

### Why eBPF?

Traditional kernel modules are compiled into the kernel and a bug can crash the whole OS. eBPF programs are **verified by the kernel before they run** — the verifier mathematically proves the program cannot crash or access invalid memory. If verification fails, the program is rejected entirely and nothing is loaded.

### Why XDP?

XDP is the hook point at the network driver level — earlier than `iptables`, `nftables`, or even the kernel's routing table. At XDP, a packet drop is just "don't give this packet to the driver stack" — the cheapest possible operation. For DDoS mitigation or large blocklists, this matters enormously.

---

## Features

- **XDP packet dropping** — blocks traffic at the driver layer, before the OS sees it
- **IP blocklist** — block any IPv4 address with a single command
- **Persistent rules** — blocked IPs survive firewall restarts and reboots
- **Offline management** — add/remove IPs even when the firewall is stopped
- **Global kill switch** — drop all incoming traffic with one flag (not yet exposed as CLI command, map-level feature)
- **Live logging** — real-time stream of every dropped packet with source IP, destination IP, and drop reason
- **Fragment dropping** — automatically drops fragmented IPv4 packets to prevent filter bypass
- **Safe failure mode** — if the eBPF program hits any unexpected state, it passes the packet (fail-open), so a bug in the firewall does not take down your network connectivity

---

## Project Structure

```
plasmawall/
│
├── setup.sh                  ← One-shot environment setup script
│
├── firewall-common/          ← Shared types (compiled for BOTH kernel and userspace)
│   └── src/lib.rs            ← PacketLog struct, Action/Reason enums, constants
│
├── firewall-ebpf/            ← The eBPF kernel program (runs inside the kernel)
│   └── src/
│       ├── main.rs           ← XDP entry point, map declarations
│       ├── engine.rs         ← Core packet evaluation logic
│       ├── packet.rs         ← Raw packet header parsing (Ethernet, IPv4)
│       └── lib.rs
│
└── firewall/                 ← The userspace CLI tool  (`plasma` command)
    ├── build.rs              ← Compiles the eBPF crate as part of the build
    └── src/
        ├── main.rs           ← CLI entry point and subcommand routing
        ├── config.rs         ← Path constants (PIN_DIR, BLOCKLIST_FILE, etc.)
        ├── core/
        │   ├── ebpf.rs       ← Load, attach, and detach the XDP program
        │   ├── maps.rs       ← Read/write kernel eBPF maps (blocklist operations)
        │   └── logger.rs     ← Async per-CPU perf event reader (live logs)
        ├── commands/         ← One file per CLI subcommand
        │   ├── start.rs
        │   ├── stop.rs
        │   ├── status.rs
        │   ├── block.rs
        │   ├── unblock.rs
        │   └── list.rs
        └── storage/
            └── persistence.rs ← Save/load blocklist to /etc/plasmawall/blocklist.txt
```

---

## Prerequisites

| Requirement | Minimum version | Notes |
|---|---|---|
| Linux kernel | 5.15 | 6.1+ recommended for best BTF support |
| Rust | nightly | Handled automatically by `rust-toolchain.toml` |
| clang + llvm | Any recent | Required for eBPF compilation backend |
| libelf | Any | For parsing eBPF ELF objects |
| bpf-linker | Latest | Installed by `setup.sh` via `cargo install` |

Supported distros: **Ubuntu/Debian**, **Fedora/RHEL**, **Arch Linux**.

---

## Quick Setup

Clone the repo and run the setup script. It handles everything — detecting your distro, installing system packages, installing Rust nightly, and doing a test build.

```bash
git clone <repo https web url (click on clone to get the link)>
cd plasmawall
chmod +x setup.sh && ./setup.sh
```

The script installs:
- `clang`, `llvm`, `libelf-dev` — system packages
- `rustup` with the `nightly` toolchain and `rust-src` component
- `bpf-linker` — the eBPF-capable linker (via `cargo install`)

After it finishes, your environment is ready. No manual steps needed.

---

## Building

```bash
cd firewall
cargo build --release
```

The build automatically compiles the eBPF kernel program first (via `build.rs`), then compiles the userspace CLI that embeds it.

To install the CLI globally:

```bash
sudo cp ../target/release/plasma /usr/local/bin/plasma
```

---

## Usage

> All `plasma` commands require `sudo` because they interact with the kernel (loading eBPF programs, accessing pinned maps in `/sys/fs/bpf/`).

### Find your network interface name

```bash
ip link show
```

Common names: `eth0`, `enp1s0`, `ens3`, `wlan0`. Use the one that has your actual network traffic.

---

### Start the firewall

Attaches the XDP program to your network interface. All blocked IPs from your saved list are immediately loaded into the kernel.

```bash
sudo plasma start --iface enp1s0
```

The firewall runs in the background. The `plasma start` process exits immediately — the XDP program stays attached because its kernel resources are **pinned** to `/sys/fs/bpf/plasmawall/`.

---

### Check firewall status

```bash
sudo plasma status
```

Output when active:
```
Firewall is ACTIVE
Blocked IPs: 3
```

Output when stopped:
```
Firewall is INACTIVE
```

---

### Block an IP address

```bash
sudo plasma block 8.8.8.8
```

This does two things simultaneously:
1. Writes the IP to `/etc/plasmawall/blocklist.txt` (survives reboots)
2. Inserts the IP into the live kernel map immediately (effective right now)

If the firewall is not running, only step 1 happens — the IP is queued and will be loaded automatically on the next `plasma start`.

---

### View all blocked IPs

```bash
sudo plasma list
```

If the firewall is running, reads directly from the live kernel map. If stopped, reads from the saved file.

---

### Unblock an IP address

```bash
sudo plasma unblock 8.8.8.8
```

Removes the IP from both the kernel map and the saved file.

---

### Watch live packet drop logs

Open a second terminal and run:

```bash
sudo plasma log
```

Output:
```
[DROP] 8.8.8.8 -> 192.168.1.5 (reason: BLOCKLIST)
[DROP] 1.2.3.4 -> 192.168.1.5 (reason: BLOCKLIST)
```

Each line represents one dropped packet in real time. Press `Ctrl+C` to stop.

---

### Stop the firewall

```bash
sudo plasma stop
```

Detaches the XDP program from the interface and cleans up all pinned kernel resources. Your blocklist file is preserved — `plasma start` will reload it.

---

## Full Workflow Example

```bash
# 1. Start the firewall on your interface
sudo plasma start --iface enp1s0

# 2. Check it's running
sudo plasma status

# 3. Block some IPs
sudo plasma block 8.8.8.8
sudo plasma block 1.1.1.1

# 4. Confirm they're in the list
sudo plasma list

# 5. In another terminal, watch live drops
sudo plasma log

# 6. Unblock one
sudo plasma unblock 1.1.1.1

# 7. Stop when done
sudo plasma stop
```

---

## How a Packet Gets Evaluated

Every packet that arrives on your interface goes through this exact sequence inside the kernel, in microseconds:

```
Packet arrives at NIC
        │
        ▼
[ Is it IPv4? (EtherType 0x0800) ]
        │ No → PASS (we don't handle IPv4, IPv6, ARP etc.)
        │ Yes
        ▼
[ Is the IP version field == 4 and header length >= 5? ]
        │ No → PASS (malformed, let the OS deal with it)
        │ Yes
        ▼
[ Is the packet fragmented? ]
        │ Yes → DROP (fragments can bypass port filtering)
        │ No
        ▼
[ Is global drop enabled? (CONFIG[0] == 1) ]
        │ Yes → DROP + LOG (reason: GLOBAL_DROP)
        │ No
        ▼
[ Is source IP in BLOCKLIST map? ]
        │ Yes → DROP + LOG (reason: BLOCKLIST)
        │ No
        ▼
        PASS
```

---

## Data Persistence

Blocked IPs are stored in plain text at `/etc/plasmawall/blocklist.txt`, one IP per line:

```
8.8.8.8
1.2.3.4
203.0.113.42
```

This file is written atomically (write to `.tmp`, then rename) to prevent corruption if the process crashes mid-write. On `plasma start`, this file is read and all IPs are loaded into the kernel map.

Kernel state (maps, XDP attachment) lives in `/sys/fs/bpf/plasmawall/` via BPF filesystem pinning. This directory is cleaned up on `plasma stop`.

---

## Security Notes

- **Fail-open design** — if the eBPF program encounters any parse error (malformed packet, unexpected header), it passes the packet rather than dropping it. This ensures a bug in the firewall doesn't cut off legitimate traffic.
- **Fragmentation blocking** — all fragmented IPv4 packets are dropped unconditionally. Fragments are a common technique for bypassing stateless firewalls.
- **No payload inspection** — PlasmaWall is a Layer 3/4 firewall. It reads only IP headers, not application data. This keeps it fast and avoids privacy concerns.
- **eBPF verification** — the kernel verifier rejects the program if it detects any possible out-of-bounds memory access, infinite loop, or unsafe operation. The program cannot run unless it passes.

---

## Roadmap

- [ ] Port-based filtering (TCP/UDP/ICMP)
- [ ] Full rule matching: Source IP + Destination IP + Port + Protocol
- [ ] Rule priority ordering
- [ ] Rate limiting (SYN flood protection)
- [ ] IPv6 support
- [ ] `plasma log` output to file / syslog
- [ ] Auto-load firewall on boot (systemd service)
- [ ] Named rule sets

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
