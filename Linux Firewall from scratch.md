# Linux Firewall from Scratch: Architecture & Concepts

### Stateless vs. Stateful Firewalls

| Firewall Type | Core Characteristic | Behavior |
| --- | --- | --- |
| **Stateless** | Isolated Evaluation | Blindly follows rule tables. Does not remember outgoing requests, making it susceptible to masked attacks. |
| **Stateful** | Context-Aware | Remembers connection states. Infers context from active conversations to prevent attacks. |

---

## The Packet Lifecycle & Architecture

When a packet arrives at a socket, it travels through the following firewall pipeline:

1. **Packet Interception (Kernel Space):** The firewall catches the packet using Netfilter hooks.
2. **Packet Parsing:** Extracts the Ethernet Header, IP Header, and Transport Layer Header.
3. **Stateless Rule Application:** Initial stateless rules are evaluated (e.g., dropping obvious spoofed IPs).
4. **Stateful Engine (Connection Tracking):** Acts as a smart bouncer. It identifies conversations using a 5-tuple fingerprint (Source IP, Dest IP, Source Port, Dest Port, Protocol).
* Stores fingerprints for new conversations.
* Allows free communication for established conversations.
* Closes tracked conversations upon completion.


5. **Stateless Fallback:** If the stateful engine identifies a brand-new connection, it falls back to matching the headers against a HashMap of rules.
6. **Packet Execution:** Returns a final verdict:
* `NF_ACCEPT`: Continue transmission.
* `NF_DROP`: Silently discard.
* `NF_QUEUE`: Send to User Space for further inspection.



---

## Rule Management (User Space)

To manage the firewall dynamically without recompiling the kernel:

* **CLI Tool:** A user-space application parses user commands.
* **Storage:** Creates a HashMap to store the requested packet rules.
* **Transfer:** Moves rules from user space to kernel space using Netlink Sockets or a character device interface.

---

## Common Network Attacks & Defenses

| Attack Type | The Attack | The Defense |
| --- | --- | --- |
| **SYN Floods (DDoS)** | Attacker sends thousands of TCP `SYN` packets without completing the handshake, exhausting server RAM. | Stateful firewall tracks half-open connections and enforces **Rate Limiting** (e.g., max 20 SYN packets/sec per IP). |
| **Port Scanning** | Attacker pings multiple ports (via Nmap) to find vulnerable services (SSH, HTTP). | **Default Deny Policy**. Silently `DROP` packets for unlisted ports instead of sending `REJECT`, slowing the attacker. |
| **IP Spoofing** | Attacker modifies the header to fake a trusted internal Source IP (e.g., 192.168.1.50) from the outside. | **Ingress/Egress Filtering**. Strict stateless rule to drop external packets claiming an internal IP. |

---

## Development Setup: Rust & eBPF (Aya Framework)

**System Prerequisites**

* Set up a Virtual Machine using **QEMU** (Quick Emulator) and **KVM** (Kernel-based Virtual Machine).
* Choose a Linux distribution running **Kernel 6.1 or newer** (ensures stable eBPF features and Rust support).
* Install the Toolchain: Rust **Nightly**, LLVM & Clang, `bpf-linker`, and `bpftool`.

### Required Dependencies (Crates)

Because of the strict boundary between Ring 0 and Ring 3, the project requires two distinct environments.

| Environment | Characteristics | Required Crates |
| --- | --- | --- |
| **Kernel Space (eBPF)** | Restricted. Only core functionality enabled. No standard library (`no_std` enabled, meaning no standard `Vec`, `Stack`, `Map`, etc.). | `aya-ebpf` (hook interaction & HashMaps), `network-types` (safe Rust network headers), `aya-log-ebpf` (kernel-to-user logging). |
| **User Space (CLI)** | Unrestricted. Everything allowed. Full standard library access. | `aya` (eBPF loader), `tokio` (async runtime), `clap` (CLI command creation), `anyhow` (error handling), `aya-log` (catches kernel logs). |

---
