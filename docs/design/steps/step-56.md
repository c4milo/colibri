# Design §8 step 56: the engine's empty polls on h11, 2026-11-17

[Design §8, the build plan](../../design.md#8-build-plan)

[#133](https://github.com/c4milo/colibri/issues/133). The owner ruled the internal work first: no
public name changes.
- **The cost.** Native counters on h11-many, the same on io_uring and on epoll, gave per
  request:
  - 8 calls of the engine's `receive`, of which 6 reported nothing;
  - 4 polls of the connection, of which 3 found nothing;
  - 4.9 calls of the connection's `receive`, 4 of them with no bytes.

  Each program call, and each read, marks a connection as changed. The next poll then ran the
  connection's whole `receive`, its protocol read included, to learn that no event waited. The
  judge's profile of main
  ([run 44131797472](https://github.com/c4milo/colibri/actions/runs/44131797472)) put 27% to
  29% of h11-many's user samples in the engine and 28% in the connection.
- **56a, refused.** h11 read no head from a call with no bytes. Laptop callgrind, on epoll,
  counted about 160 instructions less a request. The judge found every input within the noise
  ([run 44126759609](https://github.com/c4milo/colibri/actions/runs/44126759609)), so the
  change did not land. The laptop probe ran Rotor on epoll, because the container blocks
  io_uring, and valgrind cannot run io_uring. It may explain a result of the judge, and it does
  not choose one.
- **56b.** `connection_owed.reads_with_no_input` names each event that a call with no bytes
  can bring. `Connection.receive` skips `receive_event` when the call brings no bytes and the
  check says no. The deadlines fire and are observed either way (INV-31).
  - h2, a connection with no protocol yet, and TLS read as before. The test comes first, so h2
    pays one compare.
  - An h11 connection in cleartext reads for a 100 owed, a `done` owed, and a body's `end`
    owed. While bytes wait unread, a call with none reads nothing. A head, a body, a
    discarded body and a tunnel read nothing with no bytes: a body's decoder takes only the
    bytes of the call and gives back what it could not decode, which then waits unread.
  - Two assertions: only h2 owes a `cancelled` on a deadline, and an h11 connection is open
    or closed.
  - **Mutations, 7 of 8 CAUGHT,** against the tests of `server`, `sim`, `sim-run`,
    `colibri` and `testing`: a 100 owed, a `done` owed, h2 and TLS, TLS alone, h2 alone, an
    `end` owed, and a skip that ignores the bytes. NOT CAUGHT: no deadline observed on a
    skipped read. Each change of an h11 connection is followed by a read that reports
    `done`, or by a `send`, and both observe. INV-31 keeps the call.
- **The cost to h2, and its fix.** The judge measured 56b at `b8f8be48` against `a4058b7b`
  ([run 44155107857](https://github.com/c4milo/colibri/actions/runs/44155107857)). In user
  instructions h11-many won in both jobs, 0.9418 and 0.9373, and h11-one 0.9670 and 0.9676.
  Each h2 input stayed within the noise, but 12 of the 14 ratios of h2 were above 1, from
  1.0011 to 1.0042. callgrind on the laptop counted the test-only server's instructions on
  h2-many, 100,000 requests over h2 in cleartext:

  | Tree | Instructions a request |
  | --- | ---: |
  | `a4058b7b`, main | 10,640.6 |
  | `b8f8be48`, 56b | 10,694.8 |
  | `6c1195ab`, 56b with `receive_event` inline | 10,612.7 |

  - With the test of a call that can report nothing, LLVM made `receive_event` a function of
    its own, and each call of `receive` paid a call and a return. `receive_event` is now an
    `inline fn`, and `receive` holds the read again.
  - On h11-many the same probe counted 15,618 instructions a request on main, 14,500 on
    `b8f8be48` and 14,208 on `6c1195ab`. The laptop probe runs Rotor on epoll, so it explains
    the judge's result and does not replace it.
- **Checked, 2026-11-17,** on `6c1195ab`:
  - The judge measured it against `a4058b7b` in two jobs, with the h11 inputs
    ([run 44161211732](https://github.com/c4milo/colibri/actions/runs/44161211732)). In user
    instructions h11-many wins in both jobs, 0.9305 and 0.9328, from about 13,300 to 12,400 a
    request, and h11-one 0.9680 and 0.9677, about 650 fewer a connection. In instructions
    h11-many wins in both jobs, 0.9741 and 0.9747. Each other input is within the noise, and
    none loses. 13 of the 14 ratios of h2 are below 1, from 0.9960 to 1.0001.
  - `tools/ci.sh` passed 31 sections, with Zig 0.16.0 on an Apple M1 Pro with macOS.
  - The server tests, 755 of 755, passed on x86-64 Debug in an amd64 container.
