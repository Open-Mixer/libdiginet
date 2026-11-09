<!-- SPDX-License-Identifier: GPL-3.0-or-later
     Copyright (C) 2026 Pau Aliagas -->

# libdiginet: threat model

## What it is and where it runs

- **libdiginet** (`src/`, `include/diginet/`): the frame parser and builder, the command-stream
  cursor, the decoder and the encoders for the Control|24 and ProControl. It opens no socket,
  reads no clock and allocates nothing (`include/diginet/diginet.h`, `include/diginet/diginet_codec.h`).
- **libdiginet-transport** (`transport/src/`): the session state machine, the desk mux and the
  descriptor io. Session and mux allocate nothing and start no thread; the io layer makes
  blocking system calls (`poll`, `recvfrom`, `send`, `sendto`, `posix_spawn`, `waitpid`) in
  `transport/src/diginet_io.c`. Nothing in the tree claims real-time safety; do not call the io
  layer from an audio thread.
- **diginet-packet-helper** (`tools/diginet-packet-helper.c`): opens an `AF_PACKET`/`SOCK_RAW`
  socket bound to EtherType 0x885F on every interface and passes it over descriptor 3 with
  `SCM_RIGHTS`, then exits. Takes no arguments, reads no file or environment.
- **diginet-probe** (`tools/diginet-probe.c`): a command-line test tool that wakes a desk, drives
  a few controls and logs what the desk sends.
- **Privileges**: both tools are installed with `cap_net_raw=ep` and nothing else
  (`packaging/libdiginet.spec` `%caps`, `debian/diginet-tools.postinst` `setcap`). Neither runs
  as root nor is setuid. The libraries need no privilege when the socket is handed to them.

## Inputs

| Input | Who can write it | Trusted |
| --- | --- | --- |
| Ethernet frames, EtherType 0x885F, received on the packet socket | anyone on the layer-2 segment (the desk, or any host forging its MAC) | untrusted |
| Announce body (e0/e1): version, name, MAC list | anyone on the segment | untrusted |
| Data-frame body: command stream, running status, sysex | anyone on the segment | untrusted |
| Header fields: counters, retry, command, numbytes, sum | anyone on the segment | untrusted |
| Descriptor received over the Unix socket (`diginet_packet_receive_fd`) | the helper process the library started | trusted after the `AF_PACKET` check |
| `struct diginet_session_config`, commands passed to `diginet_session_submit` and the encoders | the host application linking the library | trusted caller, range-checked |
| diginet-probe arguments (`-i`, `--fd`, `--helper`, timers) | the local user running it | trusted (local user) |
| diginet-packet-helper descriptor 3 | the local user who starts it | untrusted, checked |

There is no configuration file and no file reader (`fuzz/README.md`, "What has no harness").

## Trust boundary

The wire is the boundary. DigiNet has no authentication: a desk is identified only by its source
MAC and the Digidesign OUI 00:a0:7e (`diginet_mac_is_digidesign`), both of which any host on the
segment can forge, and the desk takes a session with whichever host answers
(`docs/overview.md`, "Network"). Everything read from the socket is untrusted. The second
boundary is local: whoever can execute `diginet-packet-helper` receives a raw packet socket
without holding `cap_net_raw` themselves.

## What the code assumes and enforces

- `diginet_frame_parse` (`src/diginet_frame.c`): refuses a buffer shorter than 30 bytes
  (`DIGINET_E_SHORT`), any EtherType but 0x885F (`DIGINET_E_ETHERTYPE`), and `numbytes` under 16
  or past the received length (`DIGINET_E_LENGTH`). The body points into the caller's buffer;
  nothing is copied.
- The header sum is computed and reported (`sum_matches`), not enforced: the session and mux
  accept a frame whose sum does not match (`include/diginet/diginet.h`, the caller decides).
- `diginet_announce_parse`: only e0/e1, body at least 33 bytes; version and name copied into
  fixed buffers, always NUL-terminated (`copy_strz`). Bytes are not filtered for printability.
- `diginet_msg_next` (`src/diginet_msg.c`): a sysex with no F7, a channel message running past
  the body, or a status byte where data is due gives `DIGINET_E_TRUNCATED`; F1..FF gives
  `DIGINET_E_STATUS`; data with no running status gives `DIGINET_E_NO_STATUS`. The cursor always
  advances, so a loop over it ends.
- `diginet_decoder_next` (`src/diginet_decode.c`): sysex payloads are size-checked per function;
  scribble text at most `DIGINET_SCRIBBLE_MAX` (8) bytes, counter exactly 8 digits.
- Outgoing: `diginet_body_check` (`src/diginet_codec.c`) refuses any body holding `F0 13 xx 70`,
  the family that writes desk memory, whole or cut short (`DIGINET_E_REFUSED`); it guards
  `diginet_frame_build`, `diginet_session_submit` and `diginet_sysex_encode`. Builders refuse a
  body over 1484 bytes (`DIGINET_E_LENGTH`) and a short buffer (`DIGINET_E_SPACE`); encoders
  refuse out-of-range values (`DIGINET_E_RANGE`).
- Session (`transport/src/diginet_session.c`): drops frames from its own MAC, frames not for its
  MAC or broadcast, and, once a desk is known, frames from any other source MAC. Config limits
  are checked at init (`max_cmds` 1..255, `max_body` 24..1484, at most 16 other host MACs). The
  queue is fixed at 512 commands (`DIGINET_E_SPACE` when full). No e2 is sent while the desk
  announces another host's session (`DIGINET_E_REFUSED`).
- Mux (`transport/src/diginet_mux.c`): only an announce from a Digidesign-OUI MAC creates a desk;
  at most 8 desks (`DIGINET_MUX_MAX_DESKS`), further ones counted in `table_full`. A known desk's
  frames on a second interface are dropped. Receive buffers are `DIGINET_MAX_FRAME_LEN` on the stack.
- `diginet_packet_receive_fd`: accepts exactly one descriptor, closes all others and any
  truncated set, and requires `SO_DOMAIN == AF_PACKET` (`-EPROTO` otherwise). The helper is
  spawned with an empty environment; `diginet-packet-helper` refuses arguments and a descriptor 3
  that is not a connected `AF_UNIX` socket.
- `diginet_packet_open`: interface name length checked against `IFNAMSIZ`.

## Fuzz coverage

Harnesses are built with ASan and UBSan and run in CI (`.github/workflows/fuzz.yml`; details in
`fuzz/README.md`).

| Untrusted input | Harness |
| --- | --- |
| Frame envelope and header | `fuzz/fuzz_frame.c`, and through the session and mux `fuzz_transport`, `fuzz_mux` |
| Announce body | `fuzz_frame` (`diginet_announce_parse`), `fuzz_transport`, `fuzz_mux` |
| Data-frame command stream and controls | `fuzz/fuzz_decode.c` (`diginet_msg_next`, `diginet_decoder_next`, `diginet_body_check`) |
| Frame sequences driving the session state machine | `fuzz/fuzz_transport.c` |
| Frames from several desks and interfaces | `fuzz/fuzz_mux.c` |
| Caller values into the encoders and personalities | `fuzz/fuzz_codec.c` |

### Gaps

- The packet socket and descriptor io (`transport/src/diginet_io.c`), including
  `diginet_packet_receive_fd`, have no harness; they are covered by `tests/test_fdio.c` and
  `tests/test_anyif.c` only.
- `diginet-packet-helper` puts no limit on who may run it: any local user who can execute it gets
  an `AF_PACKET` `SOCK_RAW` socket. Beyond the initial bind to 0x885F, the code applies no filter
  and no lock to what the receiver sends or binds on that socket. Restrict execution (file mode or
  group) where local users are not trusted.
- No authentication on the wire. Anyone on the segment can forge a desk's MAC, inject data frames
  and acks, end a session with a forged e3 or a foreign e1, or fill the 8-slot mux table with
  forged announces until they go silent. Not enforced; `docs/overview.md` asks for a dedicated segment.
- The header sum is not checked on receive.
- `diginet-probe` prints the desk's announced name and version to the terminal unfiltered; control
  characters in a forged announce reach the terminal.

## Reporting

Report a vulnerability privately through GitHub: the repository's Security tab, "Report a vulnerability".
The policy is the organisation's `SECURITY.md`.
