# The census: every control of the desk, checked

`diginet-census` walks every control a desk has, one by one, with an operator at the desk, and records what the
desk did. The inventory it walks is in the library (`include/diginet/diginet_census.h`): 1168 controls on a
Control|24, 556 the desk sends (24 faders, 24 touch caps, 312 strip buttons, 24 V-Pots, the jog wheel, 171
section buttons) and 612 the host writes (24 fader motors, 312 strip-button lamps, 24 rings, 48 meter columns, 24
sets of automation LEDs, 48 scribble addresses, the counter, the counter LEDs, 130 section-button lamps). The
section buttons and their lamps come from ReaControl24's map, read by a script into
`src/diginet_census_c24.c`, so each row there is a claim the desk confirms or contradicts, not a fact.

## Running it

```
diginet-census -i enp1s0 -o ~/census-2026-11-14          # the interface the desk is cabled to
diginet-census --any -o DIR                               # every interface (cap_net_raw, or --helper)
diginet-census --only sections -o DIR                     # the section buttons and their lamps only
diginet-census --strips 2 --only strips -o DIR            # strips 1 and 2
diginet-census --from sec_1c_10_play -o DIR               # resume at Play
```

The census wakes the desk, then for each control:

- an **input** (the desk sends it): it says what to do (`DO: press strip 3 MUTE`) and waits up to `--answer`
  seconds (default 60) for the desk. What comes is decoded: the expected control is a `PASS`, another control is a
  `MISMATCH` with the bytes and the decoded event, nothing is `MISSING`. Type `n` when nothing happens, `s` to skip,
  `q` to stop the census where it is. A release is never a mismatch, nor is the previous control still moving.
- an **output** (the host writes it): it writes the frame that exercises it (a lamp lit, a ring or a meter full,
  the fader at three quarters, the scribble showing `C03` at 0x02 and `D03` at 0x22, the counter showing 12345678,
  the LEDs all lit), asks (`LOOK: strip 3 MUTE is lit?`), and clears it after the answer. Enter or `y` is a `PASS`,
  `n` a `FAIL`, `s` a skip, `q` the stop.

Three files land in `--out DIR` (default `.`):

| file | what |
|---|---|
| `census.md` | the report: one row per control walked, its verdict and detail, and the tally |
| `census-bodies.txt` | the record: one line per input control, its slug and the bytes the desk sent, in the golden format (`s03_mute 90 08 42`); a mismatch is `MISMATCH_s03_mute` plus what came |
| `census-frames.txt` | every desk frame, timestamped, raw |

Exit 0 when every control walked passed or was skipped, 1 when one did not, 2 usage, 3 the desk is in another
host's session, 4 no desk announced, 5 the desk did not ACK a write.

## The record is a test

`tests/test_census` reads a record back: every row must name an input control of the inventory and its bytes must
decode to that control; a `MISMATCH_` or `MISSING_` row is red. The record a real desk produced goes to
`tests/golden/census-c24.txt`, and from then on `make test` holds the inventory to what the desk said: a row the
desk contradicted stays red until the table (or the decoder) is fixed, and a later change that breaks a row the
desk confirmed is red too. Until a desk record is there, the test says so and proves the inventory on the emulator
only.

The emulator run (B in `tests/test_census.c`) is the same walk with the emulator as a perfect operator: it answers
every input with the expected body plus its release, sees every write and says yes. 1168 steps, every one a PASS,
in under 30 s. A wrong operator (C) is proven to produce the MISMATCH, MISSING, FAIL and SKIP verdicts, the
`MISMATCH_` row, and the red read-back.

## What a desk run proves, and what it does not

A green read-back says: every section button in the table is where ReaControl says it is, every strip button and
fader and V-Pot sends what `docs/protocol.md` says, and every write the library encodes lights or moves what it
names. A `MISMATCH` on a section button is most likely a wrong row in `src/diginet_census_c24.c` (a name against
the wrong id): the bytes recorded are the desk's truth, and the fix is the row. A `FAIL` on a lamp the desk does
not have (the table says `lamp` for a button with no LED) is a wrong `lamp` flag. A `MISSING` input on a button that
exists is a decoder or an inventory gap, and the raw frames show what, if anything, came.

The census does not measure timing, the fader's travel or the meters' scale; `diginet-probe` has the touch test
and the keepalive test for that (`docs/probe.md`).
