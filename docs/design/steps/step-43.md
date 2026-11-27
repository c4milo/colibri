# Design §8 step 43: a protocol preference in the client, proposed 2026-11-05

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 117](../../decisions.md) as amended. It ships in v0.15.0, after step 39, whose pool files it
touches. v0.15.0 ships without step 44, which moves to v0.16.0 (the owner's ruling of 2026-11-08).
- **The public names:** the field `client.Protocols.prefer` and its type, `.tcp` by default
  or `.quic`. `colibri.ClientConfig` passes it through.
- **The rules.** With `.tcp`, the default, the pool opens TCP first and opens QUIC only once
  TCP fails. With `.quic`, the pool does what it did before: QUIC first, and TCP after the
  fallback delay. The tests and examples that expect QUIC first ask for `.quic`.
- **The checks.** The simulator's pool run with `.tcp` connects over TCP when both work, and
  over QUIC when TCP fails. A mutation that opens QUIC first under `.tcp` is caught.
- **The build, 2026-11-06.** `client.Protocols.prefer` takes `client.Transport`, which the
  root already exports, so no name joins a public list. `Config.quic_first` stayed at first: it
  says whether QUIC may open at all with no HTTPS record and no Alt-Svc.
  - Under `.tcp`, QUIC opens when this attempt's TCP failed, or when TCP is not allowed. No TCP
    slot opens while QUIC's handshake runs, and the pool sets no fallback instant.
  - A review found that the first build also opened QUIC when no TCP slot was free. A TCP
    connection that drained after a GOAWAY then opened QUIC, though TCP did not fail. With UDP
    blocked, the exchange then waited for QUIC's idle timeout. Now QUIC waits for the slot to
    close, and TCP opens in it again. Removal of the fix is **CAUGHT** by `zig build
    test-client`. The client trace check now prints `quic=81` and `states=2630`, and every
    other count stays.
  - The QUIC fixture of `src/client/pool/` asks for `.quic`, and so do `examples/client_exchange.zig`
    and the h3 tests of `src/colibri/`. `examples/colibri_server.zig` fetches over h2 by
    default and over h3 with `.quic`. The test-only client's pool mode keeps `.quic`, and
    `--tcp-first` gives the default.
  - The client trace run draws `prefer` and a TCP server that refuses each connect from a
    generator of their own. It requires the first `open` to name the preferred transport. Under
    `.tcp` it requires h2 first in a clean seed where TCP works, and h3 where TCP refuses.
  - spec/tla/client_exchanges gains the constant `Prefer`, and every configuration names it.
    The old configurations name `"quic"`. Four new ones name `"tcp"`: `ClientExchanges_prefer_tcp`,
    `ClientExchanges_prefer_tcp_completes`, `ClientExchanges_prefer_tcp_pool` and
    `ClientExchanges_h3_alone_prefer_tcp`. The client and pool trace runs write `Prefer`. TLC did
    not run here; the nightly job checks every configuration and both trace runs.
- **What was run, 2026-11-06,** on macOS 26.6.2 arm64 with Zig 0.16.0. Each exited 0:
  `zig build lint`, `zig fmt --check build.zig bench build examples src tools`, `zig build
  test`, `zig build test-sim-run`, `zig build examples`, `tools/doc_snippets.sh`,
  `tools/consumer_check.sh` and `tools/pool_interop.sh`. The client trace check printed
  `seeds=256 requests=534 responses=328 quic=82 tcp=295 prefer_tcp=137 quic_after_tcp=11
  states=2632`. `tools/pool_interop.sh` read `quic_opens=1 tcp_opens=1` with `--tcp-first`
  against aioquic, and `quic_opens=0 tcp_opens=1` against Go.
- **The mutations.** Each was **CAUGHT** by `zig build test-client`: QUIC first under `.tcp`;
  TCP beside a QUIC handshake under `.tcp`; QUIC after every TCP slot; QUIC that waits for TCP
  with no slot free; the preference ignored; `tcp_tried` never set; `.quic` as the default; the
  fallback instant set under `.tcp`. `tcp_tried` never set was **NOT CAUGHT** at first, and a
  pool test of two TCP slots now catches it. `zig build test-sim-run` **CAUGHT** QUIC first
  under `.tcp`, the preference ignored, and TCP beside a QUIC handshake.
- **The owner's rulings of 2026-11-06** (decision 117 as amended on that day):
  - The fix of the review stays. Under `.tcp`, QUIC waits for a TCP slot that closes, and opens
    only once a TCP connect failed.
  - `client.Config.quic_first` becomes `client.Config.quic_unadvertised`. The old name said
    "first", but under `.tcp` QUIC does not open first. The field says whether QUIC may open
    when no HTTPS record and no Alt-Svc name h3. Its default stays `true`.
  - The rename is a breaking change of v0.15.0. A program that sets `quic_first` does not
    compile, and it sets `quic_unadvertised` in its place.
  - The rename changed `src/client/pool/`, `src/sim/client_trace_world.zig` and docs/usage.md.
    No example, `tools/` file, `tools/consumer/` file or README names the field. The model
    `spec/tla/client_exchanges` names a `Policy`, not the field, so no `.cfg` file changed. A
    field is not on a public list, so no list changed. The entries of step 17d keep the old
    name, because they record the build of that day.
- **QUIC's close under `.quic`, 2026-11-13** (decision 117 as amended on that day). A pool under
  `.quic` opened TCP for a request that came while its QUIC connection waited out its closing
  period (RFC 9000 §10.2), after the client closed it idle (RFC 9114 §5.1). The pool then stayed
  on h2, because QUIC never opens beside an open TCP connection. A probe in
  `src/colibri/fake_host_pair_test.zig` showed it on main `4a813acd`: the QUIC slot stayed
  `draining` until the period ended, and the second GET took h2.
  - The choice's view gains `quic_carries`: the QUIC connection carries an exchange that has not
    ended. Under `.quic`, a QUIC connection that drains and carries none no longer lets TCP open.
    The exchange waits for its slot, and QUIC opens again. One that drains after a GOAWAY with
    exchanges in it still lets TCP open.
  - `spec/tla/client_exchanges` gains the same rule in `CanOpenTcp`: no TCP while QUIC drains
    and each exchange it holds ended. No `.cfg` file changes. Each configuration that checks
    `Ends` or `Completes` sets `CloseWhenDrained`, and `Close` is fair, so the slot closes and
    the exchange opens QUIC. The `tla` job checks it, because no TLC runs on a person's machine
    (decision 67 as amended on 2026-11-05). The job passed on `82fb6793` on 2026-11-14
    ([run 43588839091](https://github.com/c4milo/colibri/actions/runs/43588839091)).
  - The checks. `src/client/pool/pool_choice.zig` tests the wait, the slot that closes, a GOAWAY
    with exchanges, and a QUIC connection of this attempt. `fake_host_pair_test.zig` makes the
    second GET in the closing period: it takes h3, resumes the first session, and opens no TCP
    connection. `zig build test-client test-colibri` passed 611 of 611, and `zig build
    test-sim-run` 90 of 90 with no census changed: no simulator run sends a request in QUIC's
    closing period. On x86-64 Debug, in an emulated container, both pool tests passed. That
    binary then stops at `pool_limits_test` with a segmentation fault, and main's own binary
    stops there too, so the native `checks` job judges the rest.
  - The mutations, each against `zig build test-client test-colibri`: the rule removed;
    `quic_carries` always true; always false; the rule reading the opposite fact; the rule before
    this attempt's own QUIC; the rule for every QUIC phase that is not idle. Each was **CAUGHT**.
    `quic_carries` always false was caught by three pool tests of a GOAWAY that existed before.
