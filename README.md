Follow-up direction for next steps:

This initial setup the base XDP program and loader using Aya. The next step is to implement a stateless ruleset.

The intended design is:

- Rule storage should be implemented using eBPF maps in `firewall-ebpf` (kernel space).
- Packet filtering logic should live inside `try_firewall`, where packets are parsed and matched against rules.
- Rules should NOT be hardcoded in the kernel program. They must be inserted/updated from user space.

Suggested flow:
User space (loader / future CLI) → updates eBPF maps → kernel (XDP program) reads maps → decides PASS/DROP.

Recommended breakdown:
1. Define a shared `Rule` struct in `firewall-common`.
2. Add a HashMap in `firewall-ebpf` to store rules.
3. Parse packet headers in `try_firewall` (IP, protocol, port).
4. Perform O(1) lookup in the map and return XDP_PASS / XDP_DROP accordingly.
5. Extend the loader to populate/update rules (CLI can be added later).

Important constraints:
- Keep logic simple (no loops, no complex branching).
- Do not move filtering logic into user space.
- Maintain separation between user-space (`firewall`) and kernel (`firewall-ebpf`) crates.

this is design aligned with Aya’s model and allows easy extension to CLI + dynamic rule management later.