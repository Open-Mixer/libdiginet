# diginet-probe: the first test on a real desk

`diginet-probe` wakes a Control|24 or ProControl, drives a few controls, logs everything the
desk sends, and prints what it found. It is built on libdiginet and its transport and needs
one capability, `cap_net_raw`, to open the packet socket. Nothing else on the machine is
involved: no mixer, no DAW.

## Before the probe: a passive capture (M0)

Cable the desk to a NIC of its own (directly, or through a 10/100 switch; never a network
that carries anything else), power it on, and record two minutes without sending anything:

```
cat /sys/class/net/<if>/speed /sys/class/net/<if>/duplex
sudo tcpdump -i <if> -w c24-boot.pcap 'ether proto 0x885f'
```

Expected: `e0` frames from `00:a0:7e:…`, length 50, the name `CNTRL|24` and a version, about
7 s apart.

## Running it (M1)

```
make
sudo setcap cap_net_raw=ep ./tools/diginet-probe
./tools/diginet-probe -i <if>
```

Run `tcpdump` beside it to keep a capture of the whole session. The probe:

1. waits for the desk's `e0` announce and prints its MAC, name, version and personality;
   if the desk is in a session with another host (`e1` naming another MAC) it stops there;
2. sends `e2`;
3. requires an `a0` and then an `e1` naming this host, and prints where the host MAC sits
   in the `e1` body;
4. keeps the session alive every 10 s (`--keepalive`);
5. moves fader 1 to mid-travel (`B0 00 40 20 00`) and says whether the desk ACKed it;
6. lights strip 1 MUTE (`90 08 40`), then turns it off;
7. writes `OMX1` to strip 1's scribble at address `0x00`, asks what the desk shows (type a
   word and Enter), then writes it at `0x20` and asks again;
8. logs and decodes every command from the desk for 60 s (`--listen`): press keys, touch
   and move fader 1, turn V-Pot 1 and the jog wheel;
9. sends `e3` on exit (also on Ctrl-C).

It ends with a summary, one line per open question it can answer.

| Option | What it is for |
|---|---|
| `-i <if>` | The interface the desk is cabled to |
| `--checksum zero\|sum` | The header sum of our frames (R3). `sum` is the default; if the fader frame is not ACKed, run again with `zero` |
| `--keepalive <s>` | The keepalive interval (R5). Stretch it 10 → 20 → 40 and watch for the desk falling back to `e0` |
| `--touch-test` | R4: commands fader 1 to 25 %, then asks you to grab the cap, move it, and let go; it sends no echo and reports what the fader did while held and after release |
| `--listen <s>` | How long step 8 lasts (60 s) |
| `--desk <mac>` | Talk only to this desk |
| `--fd <n> --mac <mac>` | Use an already open descriptor instead of `-i` (a launcher that holds the capability, or the test suite) |
| `--any` | Every interface at once, in place of `-i`: one socket bound to no interface, the steps run with the first desk that appears (or `--desk`), from the MAC of its interface. Every desk that appears or goes is logged with its interface. Without `cap_net_raw` the socket comes from `diginet-packet-helper` |
| `--helper <path>` | With `--any`, always take the socket from this helper |

Exit status: 0 when every step was acknowledged; 2 for a usage error; 3 when the desk is in
another host's session; 4 when no desk answered; 5 when the desk did not ACK our data.

`setcap` has to be repeated after every rebuild: a new binary carries no capability. The packages
install the probe and the helper owned by root and the group `diginet`, mode 0750, so only root and
the members of that group run them (`usermod -aG diginet <user>`).

## Every interface, with no capability (`--any`)

`diginet-probe --any` needs no interface name. It opens one packet socket bound to no
interface, so it hears a desk on any NIC, a NIC plugged in after it started included, and talks
to the desk from the MAC of the interface the desk appeared on. Where the probe holds no
`cap_net_raw`, the socket comes from `diginet-packet-helper` (installed with that capability by
the packages, or `sudo setcap cap_net_raw=ep ./tools/diginet-packet-helper` in the tree), and
the probe says so:

```
./tools/diginet-probe --any --helper ./tools/diginet-packet-helper --listen 60
```

It logs `desk <mac> appeared on <if>` for every desk it hears and `desk <mac> gone from <if>`
when one falls silent for 30 s, and ends with `SUMMARY any interface: desks appeared on ...`.
To see that an interface added later is heard: start the probe with the desk unplugged, plug
in the USB NIC, then cable the desk to it; the desk appears on the new interface.

Which interface the desk is on is the probe's to report, not to choose: the socket hears
EtherType 0x885F on every interface, a REAC link included.
