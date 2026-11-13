# libdiginet: overview

## Network

The desk broadcasts its announce (about every 7 s while idle, measured on a ProControl); after that every frame is unicast between the desk's MAC and the host's MAC. A switch forwards these frames like any other, and machines that speak only IP ignore them, so the desk can share a segment with ordinary IP clients. What the link needs:

- The desk and the host on the same layer-2 segment. There is no IP header, so no router can sit between them.
- The desk on the untagged (native) VLAN of the host's port: it sends no VLAN tag.
- A wired path from the desk to the host. Some Wi-Fi bridges drop an EtherType they do not know; IP clients on Wi-Fi are not affected.
- Not on an interface that carries other real-time traffic, such as a REAC stagebox link.
- The ProControl's port runs at 10 Mbit/s half duplex. If a modern NIC will not settle on that, put a small unmanaged 10/100 switch between them.

DigiNet has no authentication: the desk takes a session with whichever host answers its announce. On a LAN shared with other people, give the desk and its host a segment of their own.

## Status

Early. A Control|24 has been woken, moved, lit and read with `diginet-probe` (the emulator's timings are the
measurements of 2026-10-30); the census of every control, `diginet-census`, is proven on the emulator and waits for
its first desk run, whose record becomes a test (`tests/golden/census-c24.txt`). In the tree:

1. `protocol/diginet.ksy`, the formal byte grammar, with golden-frame tests.
2. The codecs and the Control|24 / ProControl personalities.
3. The transport: session state machine, ack window, keepalive, retransmit, latest-wins coalescing, all tested against a desk emulator.
4. One packet socket for every interface, and a desk mux that runs a session per desk over it, with appeared and gone notices, so a host hears every desk on every NIC, one plugged in later included. The socket can come from `diginet-packet-helper`, so the host itself needs no capability.
5. `diginet-probe`, a command-line tool for a first test on a real desk: wake it, move a fader, light a lamp, write a scribble strip, log every press. See [probe.md](probe.md).
6. `diginet-census`, the walk of every control with an operator at the desk, against the library's inventory (1168 controls on a Control|24, the section buttons from ReaControl24's map); its record of what the desk sent reads back as a test. See [census.md](census.md).

Building and testing: [BUILDING.md](../BUILDING.md).

## Safety

The desk's system and diagnostic message family (`F0 13 xx 70 …`) can write to the desk's own memory. The library refuses to encode it.

