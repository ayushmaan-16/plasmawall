# Linux Firewall from Scratch: Architecture & Rationale

### Stateless vs. Stateful Firewalls

* **Stateless firewalls** blindly follow the rules of the hash table and do not remember outgoing requests, making them susceptible to masked attacks.
* **Stateful firewalls** are context-aware, remember things, and infer through them to prevent attacks.

> **WHY we use both:** A modern firewall does not choose one or the other; it uses them in a pipeline. We use Stateless rules *first* because they are computationally cheap and incredibly fast. If an IP is obviously spoofed, we drop it instantly without wasting CPU cycles. We only use the Stateful engine for packets that pass the initial stateless "sanity check," preserving system resources.

---

### The Architecture: Kernel Space vs. User Space

**1. Kernel Space: Packet Interception**

* Intercept a packet.
* Unpack its details and print it to the kernel log (`dmesg`).
* Netfilter Hooks / eBPF XDP Hooks.

> **WHY we do this in Kernel Space:** Speed and interception. We *must* catch the packet at "Ring 0" (Kernel Space) the millisecond it hits the network card, *before* the operating system routes it to an application. If we wait for the packet to reach User Space, it's already too late.

**2. User Space: CLI tool for rule management of packets**

* Create a HashMap to store rules for packets.
* Move them from user space to kernel space.
* Netlink Sockets or eBPF Maps.

> **WHY we split rule management into User Space:** Stability. Kernel Space is dangerous; a single crash there triggers a Kernel Panic and freezes the whole computer. By keeping the heavy logic (parsing user input, reading config files, managing large HashMaps) in standard User Space, we ensure that if our CLI tool crashes, the operating system remains perfectly stable.

---

### The Packet Lifecycle & Execution

1. **Packet Arrives at a socket** -> **Packet is parsed of its headers**
2. **Stateless rules are applied** (Could eject packet)
3. **Stateful Engine works** (conversation tracking)
4. **Stateless fallback:** If new connection, match the new connection through a HashMap of rules.

**Packet Execution:**

* `NF_ACCEPT`: Continue transmission
* `NF_DROP`: Discard
* `NF_QUEUE`: Send to User Space for further inspection

> **WHY parsing is strictly header-based (L3/L4):** We are building a Network/Transport layer firewall. Parsing only the Ethernet, IP, and TCP/UDP headers is extremely fast. We do not look at the actual payload (the website data or file contents) because doing Deep Packet Inspection (DPI) in the kernel would slow network traffic to a crawl.

---

### Connection Tracking (Conversation Tracker)

* *A "connection" is purely a logical concept—it is a shared agreement and shared memory between two computers.*
* Acts as a very smart Bouncer to prevent random access to the network.
* Identifies conversations using a fingerprint: **5-tuple = Src IP | Dest IP | Src Port | Dest Port | Protocol**.
* Stores this conversation fingerprint for `NEW` conversations, allows free communication for `ESTABLISHED` conversations, and closes them via `FIN` packets.

> **WHY Connection Tracking is mandatory:** Without it, you cannot safely browse the internet. If you send a request to a website, the website *must* send data back. A stateless firewall would block that returning data because it is "incoming traffic." Connection tracking remembers your outgoing request and dynamically punches a temporary hole in the firewall to let the returning data in.

---

### Types of Attacks and How to Protect

1. **SYN Floods (A type of DDoS)**
* **The Attack:** Attacker sends thousands of TCP `SYN` packets but never completes the handshake, exhausting server RAM.
* **The Defense:** Stateful firewall tracks half-open connections and enforces Rate Limiting. Drops excess.


2. **Port Scanning**
* **The Attack:** Attackers use Nmap to systematically ping ports to find vulnerable services.
* **The Defense:** "Default deny" policy. Silently `DROP` packets instead of sending `REJECT`.
* **WHY drop instead of reject:** Sending a "Connection Refused" (`REJECT`) packet confirms to the hacker that your machine exists and is actively blocking them. Silently dropping the packet makes your machine look like a black hole, forcing their scanner to wait for a timeout and significantly slowing down their attack.


3. **IP Spoofing**
* **The Attack:** Attacker modifies the header to fake a trusted internal Source IP.
* **The Defense:** Ingress/Egress Filtering. Drop external packets claiming an internal IP.



---

### How to Build Using Rust (eBPF & Aya Framework)

**Prerequisites for Dev:**

* **Virtual Machine (QEMU / KVM):**
* **WHY:** Writing low-level network hooks can easily severe your own internet connection or crash your OS. KVM allows you to run a safe, disposable target machine with near-native CPU speeds, keeping your host system perfectly safe.


* **Kernel 6.1 or newer:**
* **WHY:** Kernel 6.1 introduced stable support for BTF (BPF Type Format). BTF allows your compiled firewall to understand the memory layout of *any* modern Linux kernel, meaning you compile it once, and it runs anywhere without breaking.


* **Toolchain (Rust Nightly, LLVM & Clang):**
* **WHY Nightly:** Compiling code for the abstract eBPF virtual machine (the `bpfel-unknown-none` target) is still experimental in Rust. You must use the Nightly compiler to unlock this specific target architecture.



**Crates to be Used:**

| Environment | Constraints | Crates | WHY these specific crates? |
| --- | --- | --- | --- |
| **Kernel Space (eBPF)** | Restricted. `no_std` (No Standard Lib, no `Vec`, no standard heap). | `aya-ebpf`, `network-types`, `aya-log-ebpf` | **WHY:** Because the kernel lacks a standard memory allocator, we cannot use standard Rust types. `network-types` gives us memory-safe representations of C-style network headers, and `aya-ebpf` is specifically written to compile into bare-metal eBPF bytecode. |
| **User Space (CLI)** | Unrestricted. Everything allowed. | `aya`, `tokio`, `clap`, `anyhow`, `aya-log` | **WHY:** `clap` is the industry standard for parsing terminal commands. We need `tokio` (an async runtime) because our CLI program needs to sleep in the background, listening for incoming logs from the kernel or waiting for the user to press `Ctrl+C` to cleanly detach the firewall. |

---
