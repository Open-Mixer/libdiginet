# libdiginet

A C library for the Ethernet protocol of the Digidesign **Control|24** and **ProControl** control surfaces, so that any Linux mixer or DAW can drive one again: motor faders, V-Pots and their LED rings, buttons and lamps, scribble strips, meters, the counter and the jog wheel.

The surfaces talk raw Ethernet (EtherType `0x885F`), not MIDI or IP. libdiginet holds the protocol: frame and session grammar, encoders and decoders for every control, and one personality per desk. A small transport layer holds the wire: the packet socket, discovery, the online handshake, acknowledgements, keepalive, retransmit and pacing. A host links the library, or runs a thin daemon that holds the one capability raw sockets need (`cap_net_raw`) and hands the desk's commands to an unprivileged application. The desk and the host must share one layer-2 segment, on a wire.

Early, and not yet tried on a desk.

## Install

Fedora 44:

```
sudo dnf install https://www.openmixer.org/rpm/openmixer-release.noarch.rpm
sudo dnf install libdiginet-devel diginet-tools
```

Debian bookworm and trixie (also Raspberry Pi OS):

```
curl -fsSLO https://www.openmixer.org/deb/openmixer-release.deb && sudo apt install ./openmixer-release.deb
sudo apt install libdiginet-dev diginet-tools
```

## Start

`diginet-probe` wakes a desk on the wire and lets you move a fader, light a lamp and write a scribble strip (`man diginet-probe`); `diginet-census` checks every control of the desk, one by one, and records what the desk sent (`man diginet-census`). A program builds with:

```
cc app.c $(pkg-config --cflags --libs libdiginet-transport)
```

## Documentation

<https://www.openmixer.org/projects/libdiginet>, and in this repository: the network a desk needs, the status and the safety rule ([docs/overview.md](docs/overview.md)), the protocol as known, every claim cited ([docs/protocol.md](docs/protocol.md)), the probe ([docs/probe.md](docs/probe.md)), building and testing ([BUILDING.md](BUILDING.md)).

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).
