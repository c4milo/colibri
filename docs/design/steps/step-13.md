# Design §8 step 13: `bench/`

[Design §8, the build plan](../../design.md#8-build-plan)

The judge, the competitor matrix and the memory measurement, under §11's method on the
`ubuntu-24.04-arm` runner (decision 33 as amended on 2026-09-30). Eight parts; the owner ruled on
2026-09-30 that 13a and 13b come first:
- **13a**, the judge. `bench/run.sh` builds colibri's test-only servers in ReleaseSafe, pins each
  server and h2load to cores of their own, and counts the server's instructions, cycles and
  system calls with `perf stat`, per request and per connection: h2 in cleartext and over TLS,
  with many requests on a connection and with one. `.github/workflows/bench.yml` measures a
  `base` and the change in turns in one job, five rounds each after a warm-up it discards, and
  reports each input's median and spread. **Check:** two jobs of a tree against itself give the
  noise floor, which `docs/performance.md` records, and a mutant that adds a known cost per
  request loses past it.
- **13b**, static memory per connection: each connection struct's size, printed from the code
  being committed, the way chapulin's `bench/sram.sh` measures its rows. **Check:** the table in
  `docs/performance.md` matches what the build prints, and `zig build test` fails when a struct
  changes size without the table.
- **13c**, h2 against h2o and nginx under h2load, in the same job.
- **13d**, h3 against quiche and quic-go under `h2load --h3`, from `tools/h3load/`'s pinned
  build, with handshakes per second for §11.1's short connections.
- **13e**, QUIC throughput under msquic's `secnetperf`, through the `perf` ALPN endpoint of §9.
- **13f**, latency percentiles at stated offered loads, from a generator that sends on a
  schedule. The owner ruled its form on 2026-10-26: the throughput and the latency of a server
  that routes, against servers that route in other languages.
  - **The servers.** Each serves the GitHub API's 203 routes of
    `bench/router/competitors/github_routes.txt` and answers every route with 200 and `ok\n`, on
    one core. colibri's test-only server routes through `server.router` with `--routes github`.
    The competitors are Go's net/http with chi (`GOMAXPROCS=1`), Rust's axum on a single-thread
    tokio runtime, http.zig with its router and one worker, and Node's Fastify, each pinned in
    `bench/competitors/`. Over h3, which the owner added on 2026-10-26, colibri's test-only UDP
    server routes with `h3 routes=github`, chi serves through quic-go's `http3.Server`, and axum
    through quinn and the `h3` crate. http.zig and Fastify have no h3.
  - **The load.** oha, pinned by release and commit, sends GET requests over the 131 GET routes
    at fixed rates with `--latency-correction`, so the latency holds the queue time that
    coordinated omission hides. It sends h11, and h2 in cleartext with prior knowledge to every
    server but http.zig, which has no h2, and h3 over TLS to the three servers that speak it.
    It also sends h2-tls, h2 over TLS 1.3 with ALPN, to every server but http.zig, which has
    no TLS. h2-tls gives h3 a baseline with the same encryption over TCP.
    oha's release builds have no h3, so the script builds oha from its tag with the `http3`
    feature. Every server gets 32 requests in flight: 32 h11 connections, or 8 h2 or h3
    connections of 4 streams. On its one core colibri's server runs one
    worker, which holds `connections_per_worker_max`, 32, connections at once, and a 33rd waits
    unaccepted, which a load of 64 connections showed. At each rate the report gives p50, p99 and
    p99.9, and for each server the highest rate whose p99 stays under 10 ms.
  - **The method.** `bench/run.sh --latency` runs the servers in turns in one job on the judge,
    five rounds after a warm-up it discards, and reports each median with its spread. A time
    is compared only inside one job (§11.4).
  - **Sub-steps.**
    - 13f.1: the test-only server's `--routes github` mode, whose router answers every request
      from a pool of `routes_requests_max` entries for each worker. Its first build showed that
      `handle` compiled over 203 routes needs more than the default comptime budget in `start`
      and `on_finished`, which now grows with the route count.
    - 13f.2: the four competitor servers.
    - 13f.3: oha and `bench/run.sh --latency`, which runs `bench/run_latency.sh`, its report
      `bench/report_latency.py` with its `--test`, and the workflow's `latency` input. A run in a
      container on a laptop, on 2026-10-26, measured every server and wrote the report. Its
      numbers are not the judge's: at 80,000 req/s each server reached about 40,000, which may
      be oha's own ceiling on two cores, and the judge's run tells.
    - 13f.4: h3, with the UDP server's `routes=github` word, which `server.router` answers
      through `server.Endpoint` in place of the files of `<www>`. The word needs `h3`. Three
      mutations, all CAUGHT: the check of the two words always passes, `routes=github` sets
      `h3`, and the last word returns before the check. On a laptop, oha built from source got
      200 over h3 from colibri, chi and axum.
    - 13f.5: h2-tls, which the owner asked for on 2026-10-26 to tell the cost of TLS from the
      cost of QUIC. The judge's run 40422314867 found that colibri and axum hold 80,000 req/s
      over h2 and 20,000 over h3, and chi 20,000 and 10,000. The job's limit rose from 90
      minutes to 120, since the run without h2-tls took 60.
    - 13f.5 waited for chapulin a6703587. Before it, chapulin's server sent `record_size_limit`
      to a client that did not offer it, which RFC 9846 §4.3 forbids, and oha's rustls aborted
      (https://github.com/c4milo/chapulin/issues/206). The bump from 50d7d17b moved three
      pinned censuses. The TCP trace run and the h3 deadline run moved in their CRC-32s alone.
      The endpoint run kept each total, and 2 of its 1,577 requests moved from a cancel to
      `done`. On a laptop, oha sent 1,000 req/s over h2-tls for 2 s, and colibri answered
      1,999 with 200.
    - 13f.6: GSO and GRO in the UDP server's `h3` mode, which the owner ruled on 2026-10-27,
      to find whether they bring colibri's h3 p99 nearer axum's. Rotor's pin moved from
      59599a88 to d75b411, whose `DatagramOptions.coalesce` asks for UDP_GRO. The `src/testing/`
      server alone changed, and the library did not:
      - The socket asks the kernel to coalesce, into receive buffers of 66 KiB, and the server
        hands each segment of a coalesced delivery to the endpoint as a datagram.
      - Each turn, `udp_batch.zig` adds each datagram the endpoint owes to a batch for its peer
        and its codepoint, and each batch goes out as one send of segments (UDP_SEGMENT). The
        endpoint takes its connections in turn, so two datagrams in a row seldom share a peer.
      - On macOS, which has neither, each batch holds one datagram.
      - In an Ubuntu 24.04 container on a laptop, `h2load --h3` fetched a 30,000-byte file
        2,000 times, and every request succeeded. The server made 12,518 `sendmsg` calls for
        the 60,000,000 bytes, about 4 datagrams for each call.
      - Ten mutations, each CAUGHT on Linux: the peer, the codepoint, a longer datagram, the
        segment count and the byte count each ignored, a shorter datagram that does not close
        its batch, one datagram sent as segments, a delivery not split, no UDP_GRO, and a batch
        in flight that takes a datagram.
      - The judge's run 40526708637 measured `42445f1c`, and run 40516121513 measured
        `291d0d61`, the tree before. Over h3, colibri and axum held 20,000 req/s in both
        runs. The change moved colibri against axum, in each job:
        - colibri's p99 divided by axum's at 40,000 req/s went from 0.92 and 0.91 to 0.87 and
          0.84.
        - colibri's rate divided by axum's at 80,000 offered went from 1.06 and 1.05 to 1.10
          and 1.09.
      - `docs/performance.md` holds run 40526708637 as 13f's baseline.
      - The owner asked where v0.10.0 stands. The judge's run
        [41043528714](https://github.com/c4milo/colibri/actions/runs/41043528714), on the tag
        v0.10.0 (`a23be1b2`), gave each server the highest rate of the baseline, in both jobs.
        Against axum, in each job:
        - h11: the two match. At 80,000 req/s colibri's p99 was 4.82 ms and 5.13 ms, and axum's
          5.21 ms and 4.82 ms.
        - h2: colibri holds 80,000 req/s, at a p99 of 6.40 ms and 9.05 ms, and axum holds
          40,000. At 40,000 colibri's p99 was 1.02 ms and 1.16 ms, and axum's 1.83 ms and 1.84 ms.
        - h2-tls: colibri's p99 divided by axum's at 40,000 req/s was 1.29 and 1.00, where the
          baseline gave 1.34 and 1.27.
        - h3: colibri's p99 divided by axum's at 40,000 req/s was 0.87 and 0.96. Its rate
          divided by axum's at 80,000 offered was 1.03 and 1.01, where the baseline gave 1.10
          and 1.09. Steps 27 and 28 changed how colibri's QUIC connections send, and the owner
          asked to find whether they moved that rate.
        - Four judge runs measured the commits between: `aa61022f`, before decision 130 and
          after Rotor's clock fix, `e85d58fa` (decision 130), `3114731d` (decision 131) and
          `cd131e39` (step 27). The ratio at 80,000 offered was 1.03 and 1.07, 0.99 and 1.02,
          1.01 and 1.07, and 1.09 and 1.07. Its two jobs differ by up to 0.04, and it moves in
          no one direction from commit to commit. So no change moved the rate past the noise of
          this ratio, which is about 5% from one run to the next.
      - Rotor v0.9.0, 2026-11-05. The pin moves from `4f818b7` to `5a5d7d7`. Rotor now splits
        a coalesced datagram itself (its decision 15 as amended on 2026-11-05). Each segment
        arrives as an event of its own, and `segment_bytes` on a received datagram is always 0.
        - The `udp.zig` test now requires three events for the segmented send, each with its
          own bytes and a `segment_bytes` of 0.
        - `Segments.of` took 0 as one datagram, so it never split a delivery again. On
          2026-11-06 it went from `udp_batch.zig` and `datagram_batch.zig`, with its test. Each
          server now hands a delivery to its endpoint whole, and asserts a `segment_bytes` of 0.
        - `coalesce` is now true by default. Every socket with a group of 2,048-byte buffers
          sets it false or holds no group. Each buffer size is a multiple of 8, as Rotor now
          requires.
        - The test ran in an Ubuntu 24.04 arm64 container, on io_uring, and passed.
- **13h**, a profile of the server on the judge, which the owner ruled on 2026-10-27, to find
  where colibri spends its time. `bench/run.sh --profile` runs each input once after the
  warm-up, under `perf record` at 1,999 Hz with the call stacks, in place of `perf stat`. Each
  input sends its load ten times under the one record.
  `bench/report_profile.py` writes the functions with the most samples, by self and by
  inclusive share, and each input's folded stacks. The `profile` input of `bench.yml` runs it, and
  the artifact keeps the stacks. A profile is not a measurement, and no document publishes its
  numbers. `bench/run.sh` reached 499 lines, so the competitor builds moved to
  `bench/run_competitors.sh`. **Check:** `python3 bench/report_profile.py --test`, in
  `tools/ci.sh`, reads synthetic stacks.
  - Seven mutations of the report, each CAUGHT: self counts the outer frame, a function counts
    twice on one stack, a stack not reversed, a kernel frame not marked, an unknown frame with
    no file, the sample's line read as a frame, and the file left in the name.
  - In an Ubuntu 24.04 container on a laptop, perf 6.8 sampled the h2 server with `cpu-clock`
    under one h2-many load of 200,000 requests. It took 127 samples, which the report read with
    their inlined frames, so each input now sends its load ten times.
  - The judge's first run, 40563761760, sampled `cycles` and unwound stacks from DWARF. Its
    samples held kernel frames alone. The second run, 40566337675, failed: the judge's PMU
    refuses overflow interrupts, and perf 6.17 read `cpu-clock` as a hardware event. On a
    laptop, perf 7.0's DWARF unwinder gave no frame in user space, and its inlined frames had
    no namespace.
  - So the script now samples the first event of `cpu-clock`, `software/cpu-clock/`,
    `task-clock` and `cycles` that perf accepts. It walks frame pointers, which ReleaseSafe
    keeps on arm64 for Zig and for chapulin's C code, with `--no-inline`. A function that Zig
    inlined counts in the function that holds it. Run 40568694619 sampled `cpu-clock`, and
    each input's stacks held colibri's functions.
  - That profile showed 19% of h3-one's CPU in `memcpy`. `std.StaticBitSet.isSet` takes its
    set by value, and the CRYPTO window and each block of a stream's unread bytes called it
    once per byte, so each call copied 512 or 128 bytes. `src/quic/bit_runs.zig` now reads
    the sets 64 bits at a time, and a consumed CRYPTO window moves its `head`, not its bytes.
    A laptop's uprobe counted 4.2 MB of `memcpy` per h3 connection before and 19.5 KB after.
    The judge's run 40579559875 against main admitted it: h3-one fell to 0.6239 and 0.6206 of
    the base's instructions per connection, from 2,362,218 to 1,473,728 in job 1, and h3-many
    to 0.9796 and 0.9766. No input lost. `head` adds 8 bytes to each of a connection's three
    CRYPTO streams, so `quic.Connection` grew from 141,888 bytes to 141,912.
  - The owner then set the goal of no copy on a request's path, on 2026-10-27, and asked that
    every change toward it be fuzzed. A laptop's uprobe on `memcpy` counted what was left: 189
    bytes a request on h2-many, 273 on h11-many and 567 on h3-many. Three copies went:
    - the varint encoder's copy of its bytes, about 36 calls a request on h3;
    - h2's copy of a response's block into its frame, when the block fits one frame;
    - the test-only server's copy of each byte it received.
  - Each change has a fuzz property, and so do the bit scans and the CRYPTO window. Zig 0.16.0's
    `--fuzz` does not build (https://github.com/c4milo/colibri/issues/53), so each property runs
    over its corpus, every input of up to two bytes, and a pass over edge values or long
    scripts. With the unit tests off, the properties alone caught 14 of 15 mutations, and the
    fifteenth was equivalent.
  - The judge's run 40749185281 found no input lost, and h2-many's user instructions fell by 64
    a request. The owner admitted it on 2026-10-28 (`docs/performance.md`, the admission rule).
  - Two copies stay. The response body and the h11 head are written into the caller's output,
    because colibri owns no I/O. Only vectored output, an API change, could remove them, and the
    owner ruled it a later question.
  - The copies of a request's field lines into its section stay too (decision 15), as the owner
    ruled on 2026-10-28. On h2-many each one copies a line from the HPACK table. The table may
    evict that entry while the request is in use, so the section must hold its own copy.
    Decoding in place would save the copy of a literal string alone, mostly on a connection's
    first request, and it needs a public name, `http.FieldSection.tail`.
  - The owner then turned to the router's cost. A callgrind probe of `handle` on one route
    counted 2,201 instructions a request, 521 more than a dispatch by hand. `std.fmt.bufPrint`
    wrote each Content-Length, and h3 each `:status`, and a writer of digits took their place:
    2,092 instructions, 412 more than by hand.
  - No input of `bench/run.sh` routed a request, so the judge could not count the router. On
    2026-10-28 the owner asked for an input that does: `h2-routes-many`.
  - The judge's run 40766024191 admitted the writer of digits on `h2-routes-many`: 0.9910 and
    0.9911 of the base's instructions, from 17,426 to 17,268 a request in job 1. No input lost.
  - The input also priced routing in the server: 17,430 instructions a request against h2-many's
    14,000, so the router costs about 3,430 a request over the GitHub API's routes. The probe
    of one route had shown 521.
  - The owner then asked whether the match needs a better algorithm, after papers and the
    fastest routers. On a laptop, colibri's `match` took 181 ns over the 203 routes, http.zig's
    34 and matchit's 56. Callgrind split its 2,056 instructions a match: about 480 finding each
    "/", 500 in the checks of each byte, 470 in the binary search of a node's edges, and 300 in
    the walk. The owner chose two changes on 2026-10-28, and kept the generated matcher and the
    tagged DFA for later:
    - One pass (`router_path.zig`) decides each byte through a table of classes and records
      where each segment ends and whether it holds a "%". The walk searches for no "/" and no
      "%". A fuzz property and every target of up to 5 bytes of 14 bytes hold it to the checks
      it replaced.
    - Each edge carries its first 8 bytes as one integer, and the build sorts the edges in the
      order the search compares in: length, that integer, then the bytes after it.
  - Callgrind then counted 1,310 instructions a match, 36% fewer.
  - The judge's run 40774628573 admitted it on `h2-routes-many`: 0.9598 and 0.9599 of the base's
    instructions, from 17,278 to 16,584 a request in job 1. No input lost.
  - The owner then asked for route tables of well-known APIs to test the router, and for a fix
    of each pattern that real APIs use and colibri refuses. Tables of Stripe's, OpenAI's and
    Kubernetes' published descriptions, and of Parse, Google+ and the static routes of
    go-http-routing-benchmark, showed one: 25 routes of Stripe and OpenAI, a literal action
    such as `/v1/charges/search` beside a parameter route with other methods, which ruling 12
    refused as `route_hidden`. The owner ruled decision 128 on 2026-10-28, and it is built:
    - The walk takes what decides that a leaf serves the request: the mask of the methods that
      serve it for `match`, the method's text for the check, and any leaf for `stop`. It backs
      up past each other leaf, and a 405 lists the methods of each leaf it passed
      (`router_allow.zig`).
    - `route_hidden` is gone. The check of unreachable routes walks each route's method on the
      canonical paths of its own pattern. `methods_too_many` refuses a table that names more
      than `route_methods_max` methods, 10.
    - `zig build router-hidden-check` agreed with its brute force on every table of its four
      families. 816 tables that ruling 12 refused now compile, and the unreachable ones stay
      refused.
    - A fuzz property and every path of up to four segments of nine pieces, with six methods,
      hold the walk to a reference that reads no trie, over a table of Stripe's shape and one
      where three patterns match one path.
    - Mutations, 8 of 8 CAUGHT: a passed leaf's methods lost, a leaf that does not serve
      stopping the walk, the wildcard ignoring the method, HEAD not served by GET, no HEAD
      after GET in Allow, methods left in table order, every route reachable, and one method
      past the limit.
  - With decision 128 each table builds, and each route's pattern, sent as a path, finds that
    route. Callgrind on a laptop counted the instructions of one match: 844 on the static
    table, 961 on Parse, 1,008 on Google+, 1,256 on GitHub, 1,345 on OpenAI, 1,486 on Stripe and
    2,157 on Kubernetes, whose paths hold up to 8 segments. On Stripe's table httprouter does not
    start: it refuses `/v1/charges/:charge` beside `/v1/charges/search`. `run.sh`'s numbers are
    a laptop's and are never published (decision 32).
  - The tables showed a second pattern: 32 routes of Stripe, Kubernetes and OpenAI give one
    parameter position two names, which ruling 5 refused. The owner ruled decision 129 on
    2026-10-28, and it is built. The trie keys every parameter child with one segment, each
    entry holds the names of its own pattern, and `found` writes the names of the entry it
    chose. `parameter_names_differ` is gone. The fuzz property of decision 128 reads each found
    route's values by its own names, over a table whose routes name one leaf's positions
    differently. Mutations, 6 of 6 CAUGHT: parameters keyed by their names, no names written,
    the leaf's first route naming each entry, the wildcard's name lost, `same_leaf` comparing
    names, and a leaf's pattern left unnamed.
  - The judge's run 40798495858 found no input past the noise. `h2-routes-many` rose to 1.0021
    and 1.0025 of the base's instructions, from 16,557 to 16,592 a request in job 1: the copy
    of the names on `found` that decision 129 ruling 4 priced.
  - The tables showed a third pattern: 64 routes of Kubernetes end in "/", such as `GET /api/`,
    which the rule on empty segments refused. The owner ruled on 2026-10-29 that "/a" and "/a/"
    are two routes, and amended decision 122 for the last segment alone. It is built:
    - A pattern and a path may end in one empty segment, and only a literal edge matches it.
      A parameter does not match it, and the wildcard does not match a path that ends in "/".
    - `zig build router-hidden-check` agreed with its brute force on the two families of two
      routes with "/a/" and "/:x/" added, 1,406 and 1,786 tables, and on paths that end in "/".
    - `convert_routes.py` keeps the 64 routes. Each of Kubernetes' 1,172 routes, sent as a
      path, finds that route.
    - Mutations, 6 of 6 CAUGHT: the path's empty last segment refused, any empty segment
      allowed, a parameter that matches it, the wildcard that matches a path that ends in "/",
      the pattern's empty last segment refused, and any empty segment of a pattern allowed.
  - The owner then chose three cuts of `match` on 2026-10-29. Callgrind on a laptop counted
    each one over the GitHub, Stripe, Kubernetes and static tables, against 1,314, 1,523, 2,179
    and 878 instructions a match. None of them saved instructions, so none landed:
    - Frames of 8 bytes in place of 32: 1,275, 1,532 and 2,193 on the first three. ReleaseSafe
      checks each narrowed field, and the checks cost about what the smaller frames save.
    - A hash of each node's literal edges, with open addressing in place of the binary search.
      Its best form compared two words of each segment, and it counted 1,409, 1,537, 2,224 and
      848. Most nodes hold a few edges, and the search compares one integer for each.
    - A pass that decides 16 bytes at a time with vector compares: 1,342, 1,535, 2,176 and
      880. A GitHub path holds 26 bytes on average, so it fills one block and reads the rest one
      byte at a time.
  - The owner then stopped the router's work. A generated matcher, which writes one function for
    each node, is the one change left that this record does not price.
  - On 2026-11-17 connect-zig reported the match's cost on its tables of Connect methods: 4,237
    instructions a call with 1 route and 4,460 with 256. The owner asked for the published
    methods for a static set of short keys. They were compile-time hashing of switch labels
    (Neumann and Göbbert), gperf, prefix B-trees, ART, Khuong and Morin's array layouts,
    PATRICIA and HOT, and PTHash and PHOBIC.
    - A hash of each node's literal edges was measured again, and gave the result above. This
      record held that result, and the prototype should have started from it. At 256 edges of 4
      bytes it took 543 instructions a match, against 621, 492 and 608 for the first, middle
      and last edge. At 16 edges it lost in the middle by 66.
    - The cost left was the compare past a segment's first 8 bytes, which read one byte at a
      time. Each edge now keeps its last 8 bytes as one integer, in `layout.tails`, beside
      `layout.edges`, so a step over a short segment reads what it read before. A longer segment
      compares its words between, 8 bytes at a time, then the last word. The order and the
      search stay as decision 122 has them, and each edge costs 8 bytes more.
    - Callgrind on a laptop, one match over each route of a table: GitHub 1,314 to 1,297,
      Stripe 1,523 to 1,482 and Kubernetes 2,179 to 2,092. connect-zig's call at 256 routes
      went from 1,046 to 1,003. Decision 122's cases of 1 to 256 edges of 4 bytes cost 0 to 4
      fewer, except a miss at 16 edges, 2 more.
    - The checks: a test requires the words to order as `std.mem.order` orders the bytes, for
      segments of 9 to 40 bytes that differ at each byte. The test of the binary search
      against a scan of each edge gains a table of long segments of one length and one head.
    - 8 mutations, each **CAUGHT**: a middle word skipped, or its order reversed, by the tests;
      the last word's order reversed, each tail written as the head, a tail read from the first
      bytes, a node's tails taken from the table's first, a word read one byte late, and two
      equal segments never equal, by the build, whose check of hidden routes searches each table
      and finds routes that no request reaches.
    - The tests of `server` pass in Debug on x86-64 under Zig's own backend, 758 of 758, and
      those of `testing` 59 of 60. The one that fails is decision 160's test of a half-closed
      socket, which the emulation cannot run (`Unsupported`).
    - The judge, [run 44231007789](https://github.com/c4milo/colibri/actions/runs/44231007789),
      against step 13l's commit at 10 rounds: h2-k8s-routes-many wins at 0.9950 and 0.9948,
      and the server's user instructions fell from 14,731 to 14,643 a request in both jobs.
      h2-routes-many stays within the noise at 0.9991 and 0.9989, 17 fewer, and no input loses.
  - The owner also asked whether profile-guided optimization helps. Zig 0.16 has no flag for
    it. `zig cc` reads a profile with `-fprofile-instr-use` and puts its branch weights in the IR.
    With `-fprofile-instr-generate` it instruments the code, but it links no profile runtime,
    so the program writes no profile. A profile for chapulin's C code must therefore come from a
    clang of the same LLVM, 21, and it is chapulin's build to change.
  - The owner ruled on 2026-10-27 not to ask chapulin for it. Run 40568694619 showed that the
    handshakes spend chapulin's time in X25519 and SHA-256, which branch little, and PGO
    helps branches most.
- **13g**, competitors in Rust and in Zig, and four h11 inputs, which the owner ruled on
  2026-10-17:
  - hyper answers over h11 and h2, in cleartext and over TLS, from `bench/competitors/hyper/`,
    pinned by its `Cargo.lock` and its `rust-toolchain.toml`.
  - http.zig answers over h11 in cleartext alone, since it has no TLS, from
    `bench/competitors/httpz/`. It is pinned by commit and built with Zig 0.17.0, the release
    its master targets; colibri stays on Zig 0.16.
  - `bench/run.sh --h11` adds h11-many, h11-tls-many, h11-one and h11-tls-one. wrk sends them,
    not h2load: http.zig answers with an empty reason phrase, `HTTP/1.1 200 `, which RFC 9112
    §4 allows, and h2load records a status only when the reason phrase holds text. wrk sends
    for a time, one request at a time on each connection, and with `Connection: close` on the
    `-one` inputs. An OpenSSL configuration offers it TLS_AES_256_GCM_SHA384 alone, as h2load's
    option does.
- **13i**, latency on a path with delay and loss, which the owner ruled on 2026-10-29. It
  measures what h3 is for. On TCP a lost packet stalls every h2 stream of its connection, and on
  QUIC only the streams the packet carried. `bench/run.sh --latency --network`, which the
  workflow's `network` input runs, measures four profiles:
  - `clean`: no netem.
  - `far`: 25 ms each way, so a round trip of 50 ms.
  - `lossy`: the delay of `far`, and 1% of packets lost each way.
  - `mobile`: 50 ms each way with 5 ms of jitter, and 2% of packets lost each way.

  Three facts about netem set the path. Each was measured in an Ubuntu container on OrbStack's
  Linux 7.2 kernel:
  - netem reordered 1,439 of 3,000 datagrams under 5 ms of jitter. With `rate 10gbit` it
    reordered none, so each profile carries that rate, as a real link keeps its order.
  - netem keeps or drops a send of UDP segments whole. At 10% loss, 79 of 1,000 sends of 10
    datagrams arrived empty and none arrived in part, with the device's offloads on or off.
    So each h3 server sends one datagram in each send. colibri's UDP server takes the new word
    `no-gso`, quinn `enable_segmentation_offload(false)`, and quic-go `QUIC_GO_DISABLE_GSO`.
  - For TCP the device takes an MTU of 1500, and TSO, GSO and GRO turn off, so each TCP
    packet is a unit of its own too. The script puts the device back when it exits.

  colibri, chi and axum serve h2-tls and h3 at 1,000, 2,000 and 4,000 req/s, for 10 s at each
  rate. Each keeps 512 requests in flight, 8 connections of 64 streams, because 32 in flight
  cap a round trip of 100 ms at 320 req/s. The report gives each server's median p99 over h3
  divided by its median p99 over h2-tls, for each profile and rate. A new connection for each
  request, which would show h3's handshake of one round trip, is not measured yet.

  The first run, [40899079463](https://github.com/c4milo/colibri/actions/runs/40899079463) on
  `6c6d38b1`, took one round in each job. On every profile with delay, chi's and axum's p99 over
  h3 was 0.4 to 0.7 of their p99 over h2-tls, which is what h3 is for. colibri's h3 reached
  about 2,100 req/s at 50 ms and 890 at 100 ms, and its queue then pushed its p99 to seconds.
  Each connection granted 32 request streams and gave them back 16 at a time, which decision
  130 changes. Under loss, axum's h3 answered some requests with a status other than 200.

  Decision 130 adds `quic.connection_flow.data_credit_owed`, which the server's body meters
  call. [Run 40913541815](https://github.com/c4milo/colibri/actions/runs/40913541815), on
  `90968a4e` with decision 130, took 5 rounds in each job, and the two jobs agree. colibri's
  p99 over h3 divided by its p99 over h2-tls, job 1 and then job 2:
  - `far`: 0.56 and 0.56 at 1,000 req/s, and 0.65 and 0.64 at 4,000. axum's is 0.55 and 0.59,
    and chi's 0.37 and 0.40.
  - `lossy`: 0.78 and 0.77 at 2,000 req/s, and 1.34 and 1.32 at 4,000. At 4,000 colibri's p99
    over h3 is 199 ms, and chi's and axum's 107 ms.
  - `mobile`: 0.65 and 0.56 at 1,000 req/s, and 5.02 and 4.46 at 2,000, where colibri reaches
    1,666 req/s and chi 1,995. At 4,000 no server reaches the rate: chi reaches 3,277, axum
    3,084 and colibri 1,736.

  So colibri's h3 keeps up with quinn and quic-go on a path with delay, and falls behind them
  under loss at the higher rates. colibri runs RFC 9002's NewReno, and quic-go and quinn run
  CUBIC, but no run has shown that the congestion controller is the cause.
- **13j**, where a server's time goes between its requests, which the owner ruled on 2026-10-29
  for https://github.com/c4milo/colibri/issues/113. Judge run
  [40896472412](https://github.com/c4milo/colibri/actions/runs/40896472412), on `cd91ecf4`, gave
  colibri a p99 over h2-tls at 40,000 req/s of 5.89 ms and 5.34 ms, against axum's 4.75 ms and
  4.32 ms. In cleartext colibri's p99 is the lower one. colibri takes fewer instructions per
  request than hyper, on which axum runs, so the loss is in when the server runs and not in how
  much it does.
  - `bench/run.sh --latency --waits`, which the workflow's `waits` input runs, loads colibri and
    axum over h2 and h2-tls at 40,000 and 80,000 req/s, for 8 s each. One second into each load,
    tcpdump captures the heads of the packets the server sends for 0.7 s, on core 0. The report
    divides the segments with data by the rate oha reached, and gives their bytes of data each.
  - Then `perf sched record` records the server's core for 3 s. `perf sched timehist` gives each
    run of the server: how long it ran, how long it waited for the core once woken, and how
    long it slept before.
  - The report gives the median over the rounds of the runs a second, the p50, p99 and longest
    run, the p99 and longest wait for the core, and the p50 and p99 sleep, beside the latency
    of the same loads.
  - On a laptop's Linux VM it parsed the records of both servers. There both slept for
    milliseconds at p99, because oha's own pauses on the VM left gaps in the load. So only the
    judge's cores can tell the two servers apart.
  - A capture on the same VM found that colibri's h2 responses took 26 bytes of field block and
    axum's 7, because colibri wrote no response line into HPACK's dynamic table. Decision 132
    indexes them, and empties both tables after a block the encoder abandoned. Callgrind on the
    VM counted 12,544 instructions a request in cleartext before and 12,215 after.
    Mutations, 9 of 9 CAUGHT once the equivalent one was removed: the abandoned block not seen,
    no update to 0, the mirror not emptied, an insert not noted, a commit that keeps the insert
    or the owed update noted, response lines and `:status` not indexed, and the abandoned block
    not seen by h2's refused response. A line in `begin_block` that cleared the insert was
    equivalent, and is gone.
  - Judge run [40968892441](https://github.com/c4milo/colibri/actions/runs/40968892441), on
    `bed33792` against `2610f685`, admitted decision 132 in both jobs. h2-many ran at 0.9710
    and 0.9705 of the base's instructions, from 13,881 to 13,479 a request in job 1. h2-tls-many
    ran at 0.9715 and 0.9692, and h2-routes-many at 0.9801 in both. h2-one and h2-tls-one stayed
    within the noise, and no input lost.
  - Judge run [40943109670](https://github.com/c4milo/colibri/actions/runs/40943109670), on
    `2afba28b`, recorded the four loads. colibri's server never ran longer than 0.26 ms, and
    never waited for its core. At 40,000 req/s over h2-tls it ran about 4,400 times a second
    and axum's about 1,500, so colibri answers fewer requests each time it wakes. At 80,000,
    axum's rounds spread as colibri's had: in job 2 over h2 its p50 reached 186 ms. So the loss
    is not a stall in colibri. One reading is that colibri's smaller writes cost oha more
    records to read, and the capture of segments a response tests it.
  - Judge run [40990531680](https://github.com/c4milo/colibri/actions/runs/40990531680), on
    `1014dd32`, captured the segments, and does not support that reading. At 40,000 req/s over
    h2-tls, colibri sent 0.32 segments a response in both jobs and axum 0.29. Over h2 the two
    sent 0.32 and 0.31, and there colibri's p99 was 1.30 ms and 1.31 ms against axum's 1.94 ms
    and 1.92 ms.
  - The same run, with decision 132 and Rotor's clock fix, gave colibri's p99 over h2-tls at
    40,000 req/s as 3.20 ms and 3.28 ms, against axum's 2.72 ms and 2.97 ms. The owner closed
    https://github.com/c4milo/colibri/issues/113 on 2026-10-29 with that gap of about 0.4 ms
    left, since neither the server's runs nor its segments explain it.
  - **The counts and the turns, 2026-11-09.** Run
    [42558165516](https://github.com/c4milo/colibri/actions/runs/42558165516), on `5b858fe3`,
    gave colibri a p99 over h2-tls at 80,000 req/s of 25.92 ms in job 1 and 246.52 ms in job 2,
    where oha reached 78,182 req/s with a p50 of 183.94 ms. With 160,000 req/s offered, in run
    [42532331627](https://github.com/c4milo/colibri/actions/runs/42532331627), oha reached
    79,920 and 79,739 req/s against colibri, and 83,921 and 85,893 against axum. The owner asked
    for the cause on 2026-11-09.
    - After the record, `perf stat` counts the server's process for 2 s: the events of the
      judge of 13a, and `duration_time`, the time perf counted for. The load runs 11 s, in
      place of 8 s, so the counts end before it does. The report gives a table, "Counts of
      the server": the instructions, the cycles and the system calls for each request, at the
      rate oha reached, with the user's part of the first two, and the share of its core the
      server used.
    - Judge run [42748400556](https://github.com/c4milo/colibri/actions/runs/42748400556), on
      `c0510ad2`, counted the servers. Over h2-tls at 80,000 req/s, job 1 and then job 2:

      | For each request | colibri | axum |
      | --- | --- | --- |
      | instructions | 27,398 and 27,838 | 42,627 and 42,706 |
      | cycles | 17,894 and 18,514 | 30,765 and 30,949 |
      | system calls | 0.406 and 0.403 | 0.729 and 0.731 |
      | share of its core | 0.531 and 0.542 | 0.767 and 0.772 |

      So colibri's server is not the limit: about half of its core is idle. oha keeps at most
      32 requests in flight, on 8 connections of 4 streams, so the rate it reaches is 32 over
      the time of a round trip: about 0.40 ms against colibri and 0.376 ms against axum. In
      this run colibri's p99 there was 89.43 ms and 172.10 ms, with rounds from 32.06 ms to
      493.93 ms.
    - tcpdump now keeps the packets of both directions, and the script writes the server's
      port beside the capture. The report gives a table, "Turns of each connection". On each
      connection, an answer is the time from the first segment of requests after an answer to
      the first segment that answers it. A next request is the time from that segment to the
      client's next segment of requests. So the two split a round trip between the server and
      oha. The job's log names a capture whose packets the kernel dropped.
    - Judge run [42758386837](https://github.com/c4milo/colibri/actions/runs/42758386837), on
      `0ddf5a4b`, timed the turns, and no capture dropped a packet. Over h2-tls at 80,000
      req/s, the mean in ms, job 1 and then job 2:

      | Part of a round trip | Against colibri | Against axum |
      | --- | --- | --- |
      | answer | 0.032 and 0.031 | 0.071 and 0.076 |
      | next request | 0.373 and 0.351 | 0.335 and 0.311 |

      colibri answers in less than half of axum's time, and oha's side is 82% to 92% of each
      round trip. So oha and the kernel's path set the rate there, and neither server does.
      While a load keeps to its rate, the rate fixes the length of a round trip, so a shorter
      answer gives a longer wait for oha's schedule. Only colibri's load of job 1 was past its
      limit, at 76,097 req/s, so the run does not compare oha's own time against the two
      servers.
    - The loads gain a rate of 160,000 req/s, past the limit of each. There oha sends each
      request as soon as it can, so its time to the next request compares against each server.
    - Judge run [42761188584](https://github.com/c4milo/colibri/actions/runs/42761188584), on
      `dd3ad79c`, ran the three rates, and no capture dropped a packet. Over h2-tls with
      160,000 req/s offered, job 1 and then job 2, the times as means in ms:

      | Figure | Against colibri | Against axum |
      | --- | --- | --- |
      | req/s oha reached | 78,643 and 84,757 | 80,230 and 88,260 |
      | answer | 0.031 and 0.029 | 0.076 and 0.068 |
      | next request | 0.362 and 0.347 | 0.333 and 0.302 |
      | responses in a segment | 3.82 and 3.92 | 4.00 and 3.97 |
      | share of the server's core | 0.523 and 0.536 | 0.776 and 0.798 |

      A round trip takes about the same time against each: 0.393 ms and 0.376 ms against
      colibri, and 0.409 ms and 0.370 ms against axum. oha's two cores set it. colibri's
      shorter answer waits for oha, so it shows as a longer time to the next request. Each
      connection holds 4 streams, and colibri's segments carry a few responses fewer than
      axum's, so oha takes a few more turns for the same requests. oha reached 2% and 4% less
      against colibri. The two jobs differ by more: 8% against colibri and 10% against axum.
    - So over h2-tls at 80,000 req/s and past it, the load of 13f is at oha's limit, with
      colibri's server at about half of its core. A p99 at such a rate measures oha's queue,
      and does not compare the servers.
    - Mutations of the report, by `python3 bench/report_latency.py --test`, 18 of 18 CAUGHT.
      Of the counts: the warm-up's counts kept, a count divided by the offered rate, the
      user's instructions or cycles given as all of them, a count perf did not take read as
      zero, an unknown unit of task-clock read as nanoseconds, the unit ignored, a file with
      no time read, and the time perf counted for ignored. Of the turns: an acknowledgment
      that starts or ends a turn, the last segment of requests or of an answer taken in place
      of the first, connections not kept apart, the client's segments counted as the
      server's, the port file not read, either time left in seconds, and the warm-up's capture
      kept.
  - **The start of a load, 2026-11-10.** At 40,000 req/s over h2-tls, the latency run of 13f
    gave colibri a p99 of 4.93 ms and 5.20 ms, and axum 4.18 ms and 4.08 ms. The waits run of
    2026-11-09 gave 1.76 ms and 1.54 ms, and 1.76 ms and 1.63 ms. The owner asked which one is
    correct. The two runs differ in one thing: 13f loads for 5 s, and the waits run for 11 s.
    - Judge run [42828654918](https://github.com/c4milo/colibri/actions/runs/42828654918), on
      `0fe16198`, a branch not on main, loaded each server at 40,000 req/s for 5, 10, 20 and
      40 s. The p99 in ms, job 1 and then job 2:

      | Load | colibri, h2-tls | axum, h2-tls | colibri, h2 | axum, h2 |
      | --- | --- | --- | --- | --- |
      | 5 s | 5.08 and 4.33 | 4.44 and 3.88 | 1.17 and 1.17 | 1.89 and 1.86 |
      | 10 s | 1.87 and 1.72 | 1.75 and 1.88 | 1.24 and 1.22 | 1.93 and 1.83 |
      | 20 s | 1.48 and 1.86 | 1.59 and 1.56 | 1.26 and 1.27 | 1.93 and 1.86 |
      | 40 s | 1.44 and 1.40 | 1.51 and 1.40 | 1.27 and 1.26 | 1.98 and 1.89 |

      Over h2-tls the p99 falls as the load runs longer, and from 10 s the two servers match.
      Over h2 the p99 does not move. Over h2 the p99.9 rises with the time of the load, for
      both servers alike: 2.2 ms to 3.1 ms at 5 s, and 12.6 ms to 16.8 ms at 40 s. This run
      does not explain that.
    - Judge run [42857194699](https://github.com/c4milo/colibri/actions/runs/42857194699), on
      `aa75d67d`, a branch not on main, captured the packets of both directions for the first
      1.5 s of each 5 s load at 40,000 req/s. tcpdump started before oha, so each capture holds
      the SYN of each connection, and no capture dropped a packet. Over h2-tls, each range
      covers rounds 1 to 5 of both jobs, in ms:

      | Figure | Against colibri | Against axum |
      | --- | --- | --- |
      | SYN-ACK to oha's ClientHello, median | 32.7 to 33.1 | 32.9 to 33.1 |
      | ClientHello to the server's first flight, median | 0.84 to 1.13 | 0.47 to 0.59 |
      | that flight to oha's Finished, median | 0.31 to 0.61 | 0.16 to 0.26 |
      | Finished to the server's next segment, median | 0.04 to 0.07 | 0.44 to 0.71 |
      | first ClientHello to the last connection ready | 1.70 to 2.19 | 1.16 to 1.31 |
      | bytes of the server's first flight | 2,263 | 1,087 |
      | group of the key exchange | X25519MLKEM768 | X25519 |
      | p99 of the load, median of each job | 6.01 and 6.80 | 5.91 and 5.27 |

      Over h2, oha sends its first request 0.22 ms to 0.47 ms after its first SYN.
    - So oha waits about 33 ms after each TCP connect before it sends its ClientHello, against
      both servers. At 40,000 req/s, more than 1,300 requests of its plan wait before any
      connection can carry one. They fill the tail of a 5 s load, which holds 200,000
      requests. The p99 of 13f over h2-tls at 40,000 req/s therefore measures oha's start of
      TLS, and does not compare how the servers answer requests.
    - colibri's 8 handshakes take about 0.8 ms more than axum's. chapulin chooses
      X25519MLKEM768 from oha's offer, and axum's rustls chooses X25519. So colibri's first
      flight carries an ML-KEM-768 ciphertext, 1,176 bytes more, and oha takes longer to
      read it. The group is chapulin's choice, and colibri does not set it (non-negotiable 2).
  - **The tail of a long load, 2026-11-10.** Over h2 at 40,000 req/s, the p99.9 rose with the
    time of the load for colibri and axum alike: 2.2 ms to 3.1 ms at 5 s, and 12.6 ms to
    16.8 ms at 40 s. The owner asked for the cause.
    - Judge run [42932463587](https://github.com/c4milo/colibri/actions/runs/42932463587), on
      `7445a53a`, a branch not on main, loaded each server over h2 at 40,000 req/s for 5 s and
      for 40 s, in 3 rounds. oha wrote each request to its database, with `--db-url`, and
      tcpdump captured each whole load. No capture dropped a packet. The run kept each request
      slower than 2 ms, and the data segments of each direction in each millisecond.
    - oha stops at each power of two of its count of requests. In the stop, no data segment
      goes in either direction. The silence of oha's side, in ms, over each load that
      reached the count:

      | oha's count of requests | Instant at 40,000 req/s | oha silent |
      | --- | --- | --- |
      | 65,536 | 1.64 s | 2 to 4 |
      | 131,072 | 3.28 s | 6 to 7 |
      | 262,144 | 6.55 s | 12 to 16 |
      | 524,288 | 13.11 s | 27 to 30 |
      | 1,048,576 | 26.22 s | 54 to 58 |

      Each server has the stops at the same counts, and a server cannot see oha's count. The
      silence doubles each time the count doubles, as a copy of a store that doubles would.
    - oha also plans no request in a stop. It plans the requests due in the stop after the
      stop ends, so its latency correction misses most of each stop.
    - After each stop, oha sends the requests it holds as fast as the answers come back. After
      the stop at 1,048,576, the requests over 5 ms span 35 ms to 47 ms of planned starts
      against colibri, with a worst of 21 ms to 25 ms. Against axum they span 50 ms to 73 ms,
      with a worst of 26 ms to 32 ms.
    - The p99 and the p99.9 in ms, ranges over both jobs:

      | Load | colibri p99 | axum p99 | colibri p99.9 | axum p99.9 |
      | --- | --- | --- | --- | --- |
      | 5 s | 1.24 to 1.30 | 1.99 to 2.07 | 2.86 to 3.19 | 2.80 to 4.01 |
      | 40 s | 1.33 to 1.42 | 2.07 to 2.17 | 13.54 to 16.59 | 17.43 to 22.85 |

    - So the p99.9 of a load measures oha's stops. A 5 s load at 40,000 req/s holds the stops
      at 65,536 and 131,072, and a longer load holds the longer stops too. The p99 does not
      change: the requests over 5 ms are 0.33% to 0.46% of a 40 s load. The servers differ
      only in how fast the requests that oha holds after a stop are answered.
  - **A second tool, 2026-11-10.** The owner asked to check the stops with a tool other than
    oha.
    - Judge run [42936249908](https://github.com/c4milo/colibri/actions/runs/42936249908), on
      `572ccd8b`, a branch not on main, loaded each server with h2load in place of oha, in
      oha's shape: 8 connections of 4 streams, at 5,000 req/s each with `--rps`. It loaded
      over h2 for 5 s and for 40 s, in 3 rounds. h2load wrote each request to its log, and
      tcpdump captured each whole load on the same clock. No capture dropped a packet.
    - h2load times a request from its send, not from an instant on a plan. Its `--rps` sends a
      burst about every 10 ms, so a silence of 6 ms to 8 ms follows each burst. The p99 and the
      p99.9 in ms, rounds 1 to 3 of both jobs:

      | Load | colibri p99 | axum p99 | colibri p99.9 | axum p99.9 |
      | --- | --- | --- | --- | --- |
      | 5 s | 0.13 to 0.15 | 0.30 to 0.33 | 0.17 to 0.27 | 0.35 to 0.39 |
      | 40 s | 0.13 to 0.14 | 0.31 to 0.34 | 0.17 to 0.21 | 0.35 to 0.38 |

    - Under h2load the p99.9 does not rise with the time of the load. Near each power of two of
      h2load's count, the longest silence is 6 ms to 8 ms, as anywhere else in the load. So
      neither server stops at the counts where oha stops.
    - h2load has a stop of its own: one silence of 11.7 ms to 24.0 ms at 31.4 s to 33.6 s, in
      7 of the 12 loads of 40 s, against both servers. In the millisecond before it, the
      server sent as many segments as the client. The server answers in about 0.03 ms, so it
      most likely answered, and h2load read the answers when the silence ended.
  - **The h11 inputs against nginx and hyper, 2026-11-10.** colibri loses on h11 to nginx and
    hyper alone. The owner asked where the instructions go.
    - Judge run [42951238198](https://github.com/c4milo/colibri/actions/runs/42951238198), on
      `e04a8f8a`, profiled colibri's server with `h11`. On h11-one, 84% of the samples are in
      the kernel under `io_uring_enter`: the send 31%, the close 27% and the accept 10.5%. On
      h11-tls-one, X25519 takes about 30% of the samples and the P-256 signature 11%.
    - Judge run [42954423174](https://github.com/c4milo/colibri/actions/runs/42954423174), on
      `be33c75f`, a branch not on main, profiled nginx beside colibri on h11-one. `tcp_close`
      holds 23.3% of colibri's samples and 15.9% of nginx's. Only colibri's close holds
      `tcp_fin`, `tcp_time_wait` and `tcp_done`.
      - nginx closes right after its `writev`, before wrk reads the response.
      - colibri submits its close one loop turn after its send completes, and wrk has closed by
        then. On loopback the receiver's path runs inside the sender's call, so colibri's
        close also takes wrk's socket to TIME_WAIT: about 8% to 10% of colibri's samples.
      - Off loopback, colibri's close goes out microseconds after its send, and a client's FIN
        comes a round trip later. So colibri closes first there, as nginx does. A close in the
        send's turn would also need Rotor, whose close cancels the socket's send first. The owner
        ruled on 2026-11-10 to change nothing for it.
    - Judge run [42954490618](https://github.com/c4milo/colibri/actions/runs/42954490618), on
      `c082419f`, a branch not on main, profiled hyper beside colibri on h11-tls-one. X25519
      takes 28% of hyper's samples and 31% of colibri's, at equal cycles a connection. So
      chapulin's X25519 costs about what aws-lc-rs's costs, and no request went to chapulin.
    - hyper's samples hold rustls's `check_binder` and `attempt_tls13_ticket_decryption`, and
      its signature takes 0.02% of them. So wrk resumes almost every session with hyper.
      colibri's test server issues no ticket, so each connection to it runs a full handshake.
      h11-tls-one therefore compares colibri's full handshake with hyper's resumed one. The
      owner ruled step 48 on 2026-11-10: colibri's TCP servers issue tickets.
  - **h11-many and h11-tls-many against hyper, 2026-11-14.** colibri takes 1.16 to 1.22 times
    hyper's instructions a request on the two inputs. The owner asked where they go.
    - Judge run [43604566860](https://github.com/c4milo/colibri/actions/runs/43604566860), on
      `f4cd4f48`, measured the competitors with `h11`. A request takes, in job 1 and job 2:
      - On h11-many, 13,303 and 13,447 user instructions for colibri, and 7,236 and 7,195 for
        hyper. The kernel runs 22,169 and 22,178 for colibri, and 23,224 and 23,191 for hyper.
      - On h11-tls-many, 21,450 and 21,472 user instructions for colibri, and 13,172 in both
        jobs for hyper. The kernel runs 22,292 and 22,298, and 22,967 and 22,765.
      - colibri makes 0.07 to 0.11 system calls a request, and hyper 2.08.
    - So the kernel's work is equal, and the whole loss is in user space: about 6,150
      instructions a request in cleartext, and about 2,150 more in the TLS record path. By CPU
      time colibri wins h11-many, at 0.86 and 0.90 of hyper's. On h11-tls-many it takes 1.01
      and 1.13 times hyper's.
    - Judge run [43604640176](https://github.com/c4milo/colibri/actions/runs/43604640176), on
      `f9d19171`, a branch not on main, profiled hyper beside colibri on the two inputs. On
      h11-many, four functions hold about 38% of colibri's samples in user space: the engine's
      `State.receive` 13%, the connection's `read_protocol` 10% to 12%, the test worker's
      `handle` 8% and `Connection.receive` 6%.
    - The TLS record path. On h11-tls-many, chapulin's `aead_start` and `compute_powers` hold
      1.05% to 1.09% and 0.57% to 0.63% of all colibri's samples. The seal and the open of the
      data hold 1.6% to 1.7% together. chapulin computes the GHASH key and its powers again for
      each record, and aws-lc keeps them for the life of the key. The owner ruled on
      2026-11-14, as chapulin's decision 234, that a host object stores the powers beside each
      stored AES schedule. colibri gets that with a later pin of chapulin.
    - The engine. A local experiment counted the test server's calls of `receive` under
      callgrind on a laptop, whose instruction counts are never published. A request takes 7
      calls, and 5 of them take nothing and report nothing. `src/colibri/server_pump.zig` has
      the same two loops. A `server.Event` takes 160 bytes and a `ReceiveResult` 192, and each
      call returns one by value. The session that owns the engine has the numbers.
    - chapulin's decision 234, pinned at `72ed3509` with v0.7.0. Judge run
      [43648917274](https://github.com/c4milo/colibri/actions/runs/43648917274), on `02d75cc4`
      against main `21433cdf`, with `h11` and `h3` at 10 rounds:
      - h11-tls-many takes 0.9890 and 0.9882 of main's instructions, and 0.9788 and 0.9783 of
        its user instructions. That wins past the noise in job 2 alone; job 1's noise was 3.02%
        on user instructions. A request saves about 460 user instructions, the work of the
        GHASH powers of its two records. That is about 6% of the gap to hyper.
      - h11-tls-one takes 1.0022 and 1.0024, within the noise of 0.50%. Each key a connection
        derives now computes its powers once, which costs about 2,000 user instructions.
      - h2-tls-one takes 0.9963 and 0.9965, within the noise, from v0.7.0's faster P-256 and
        ML-KEM. Every other h11, h2 and h3 input is within the noise in both jobs.
    - Where the rest goes, from run 43604640176's profile, whose samples count cycles. Of the
      user-space samples on h11-many, in job 1 and job 2:

      | Part | colibri | hyper |
      | --- | --- | --- |
      | HTTP parse and write | 19.4% and 18.8%, h11 and http | 36% and 36%, hyper, http and httparse |
      | The loop | 9.1% and 8.7%, Rotor | 25% and 26%, tokio and mio |
      | The engine and the connection | 54.4% and 56.2% | none of its own |
      | The test server | 11.1% and 11.1% | none of its own |
      | Copies and scans | 5.2% and 4.5% | 6% and 6%, with malloc |
      | System calls' wrappers and the rest | under 1% | about 30%, with libc's recv and writev |

      - At about 13,300 user instructions a request for colibri and 7,200 for hyper, h11 and
        http take about 2,500 and hyper's HTTP code about 2,600. Rotor takes about 1,200, and
        tokio's loop about 1,800.
      - So the gap is in the engine and the connection, about 7,300 a request, and the test
        server, about 1,450. The session that owns the engine has these numbers.
      - The two largest repeats in h11 are small. `method.standard` runs 4 times a request,
        about 240 instructions to save, and the Host check runs again on each request, about
        190. Each is below the judge's noise on h11, so this step changes neither.
- **13k**, bulk downloads at a bottleneck, which the owner ruled on 2026-10-30 in
  [decision 136](../../decisions/0136-bbrv3-draws-its-probe-waits-from.md). The loads of 13i keep each connection's window at its first
  12,000 bytes, so they cannot tell two congestion controllers apart. This input fills the
  path, so the controller sets the rate.
  - `bench/run.sh --latency --bulk`, which the workflow's `bulk` input runs, holds the path
    with tc on the loopback device in two profiles:
    - `bottleneck`: 25 ms each way and a rate of 20 Mbit/s, with a queue of 1,000 packets. The
      path holds about 125,000 bytes, and the queue about 12 times that.
    - `bottleneck-lossy`: the same, and 1% of packets lost each way.
  - A prio qdisc puts the packets the server sends through the bottleneck, by their source
    port, and every other packet through a netem with the delay alone. So the client's
    acknowledgments wait in no queue behind the data, as on a real path.
  - The servers serve one file of 2 MiB, which takes 0.84 s at 20 Mbit/s. oha downloads it
    again and again for 30 s, from 1 and then 4 connections, one download at a time on each.
    It downloads over h3 from colibri, chi and axum, and over h2-tls from chi and axum, whose
    TCP is the kernel's, as the baseline.
  - A second oha sends one small GET each 100 ms on a connection of its own. Its p50 and p99
    give the delay the queue adds.
  - The report gives, for each server, profile, protocol and count of connections, the p50 and
    p90 download time, the goodput, and the p50 and p99 delay of the small GETs. 30 s holds
    about 35 downloads, too few for a p99.
  - The judge ran it on 23ea296, with 3 rounds in each of two jobs
    ([run 41071340342](https://github.com/c4milo/colibri/actions/runs/41071340342)). Every
    download and every GET was answered 200. The figures below give each job's median:
    - `bottleneck`: every server and protocol fills the path, at 16.78 to 18.45 Mbit/s. With 1
      connection colibri's GET p99 is 127 ms, the lowest. With 4 it is 509 and 598 ms, against
      385 and 392 ms for chi over h3.
    - `bottleneck-lossy`, 4 connections: colibri's goodput is 8.39 and 8.95 Mbit/s, the lowest.
      chi over h3 gives 12.86 and 13.42, axum over h3 9.51 and 10.07, and h2-tls 11.74 to 12.86.
    - `bottleneck-lossy`, 1 connection: colibri gives 1.68 and 2.24 Mbit/s, chi over h3 3.36 and
      3.91, axum over h3 2.24, and h2-tls 2.80 to 3.36.
    - So CUBIC loses about a third of chi's goodput under 1% loss. Step 29 measures BBRv3 on the
      same input.
  - Step 29 adds a run where a colibri server with CUBIC and one with BBRv3 share the
    bottleneck, each with 2 connections. The report gives each one's goodput and Jain's index
    of the two.
- **13l**, the Kubernetes API's routes, which the owner ruled on 2026-11-17. connect-zig asked
  for a cheaper match on route tables of its size, and the GitHub API's routes cannot show
  a change to the compare of long segments.
  - `h2-k8s-routes-many`: h2-many against the server with `--routes kubernetes`. Its router
    holds the 463 routes of `bench/router/competitors/kubernetes_sample_routes.txt`, and h2load
    sends the table's 228 GET routes in turn, each parameter given a value.
  - The sample holds 235 of the API's 587 paths, each with every method it has: the paths at
    places 0 and 2 of each 5, in the file's order. The owner asked on 2026-11-17 for about 500
    routes of mixed methods and paths. A cold Debug build and run of the `testing` module takes
    30 s on main. All 1,172 routes added 42 s to it, and the sample adds 10 s.
  - The sample keeps the API's mix of methods within 1 point, all 24 of its API groups, and its
    largest node, of 23 edges. 220 of its 352 literal edges are longer than 8 bytes, and 88 are
    longer than 16. Of the GitHub API's 120, 32 are longer than 8, and none is longer than 16.
  - A tree whose server names no such table, one from before this step, does not run the
    input: `serves` reads the server's usage. The report then gives the input without a verdict.
  - The judge first ran it in
    [run 44231007789](https://github.com/c4milo/colibri/actions/runs/44231007789), with this
    step's commit as the base, at 10 rounds. Both trees served the input, and every request was
    answered. The base counted 17,136 and 17,139 instructions a request in the two jobs, against
    15,801 and 15,802 on h2-routes-many, with spreads of 0.15% or less.
- **13m**, the README's charts, which the owner asked for on 2026-11-18, as connect-zig and
  chapulin show theirs. `bench/chart.py` draws three SVGs into `docs/images/` from the first job
  of one named run, and the README's Performance section shows them:
  - `cpu`: the CPU time a request of each server, from a report of `--competitors --h11 --h3`.
  - `throughput`: the requests a second each server serves at full load, from a report of
    `--throughput` since 13q. Before 13q it read the most requests a second each server answered
    at any rate of `--latency`.
  - `latency`: each server's p99 at each rate of the same report, on log scales, with the bound.
  - Each bar chart's title says where colibri is best, where another server ties it, and where
    another server is better. Two servers tie when their values differ by no more than the
    larger of their two spreads, the noise `bench/report.py` judges a change by. So a title
    claims no win inside the noise.
  - The first charts come from job 1 of run
    [44446759723](https://github.com/c4milo/colibri/actions/runs/44446759723), the
    competitors, and of run [44445591237](https://github.com/c4milo/colibri/actions/runs/44445591237),
    the latency, both on main at `89045d95`.
  - On 2026-11-19 the three charts were drawn again from job 1 of three runs on main at
    `15364872`: [44550549712](https://github.com/c4milo/colibri/actions/runs/44550549712), the
    competitors at the versions of 13p, with Go's servers of 13o;
    [44550555216](https://github.com/c4milo/colibri/actions/runs/44550555216), the throughput of
    13q; and [44550560431](https://github.com/c4milo/colibri/actions/runs/44550560431), the
    latency. In the throughput chart each bar now gives colibri's rate as a multiple of the
    other server's, so a larger number means colibri serves more. The axis writes a million as
    `1M`.
  - The same day they were drawn again from job 1 of three runs at `70f186c1`, with axum on quinn
    in the h3 panels (13r): [44580815826](https://github.com/c4milo/colibri/actions/runs/44580815826),
    the competitors; [44580833490](https://github.com/c4milo/colibri/actions/runs/44580833490),
    the throughput; and [44580848285](https://github.com/c4milo/colibri/actions/runs/44580848285),
    the latency.
  - The owner ruled on 2026-11-19 that each new release tag gets the charts drawn again, from
    three runs of `bench.yml` on the tag. For v0.19.0, on `4c41e44a`, they come from job 1 of
    [44625801787](https://github.com/c4milo/colibri/actions/runs/44625801787), the competitors;
    [44625817873](https://github.com/c4milo/colibri/actions/runs/44625817873), the throughput;
    and [44625833094](https://github.com/c4milo/colibri/actions/runs/44625833094), the latency.
    For v0.20.0, on `c1aceb59`, they come from job 1 of
    [45630159962](https://github.com/c4milo/colibri/actions/runs/45630159962), the competitors;
    [45630164036](https://github.com/c4milo/colibri/actions/runs/45630164036), the throughput;
    and [45658737912](https://github.com/c4milo/colibri/actions/runs/45658737912), the latency.
    The latency of the first run on the tag,
    [45630168558](https://github.com/c4milo/colibri/actions/runs/45630168558), put colibri's p99
    over h2 at 80,000 at 10.42 ms, past the bound. The owner asked for a second run, whose job 1
    the chart gives, and docs/performance.md states the four jobs' range.
    For v0.21.0, on `2ab43623`, they come from job 1 of
    [45719659691](https://github.com/c4milo/colibri/actions/runs/45719659691), the competitors,
    which measured `5847a115` before the tag moved to `2ab43623`, whose code is the same;
    [45726731806](https://github.com/c4milo/colibri/actions/runs/45726731806), the throughput;
    and [45726735781](https://github.com/c4milo/colibri/actions/runs/45726735781), the latency.
    For v0.22.0, on `3ac8c7bc`, they come from job 1 of
    [45898056242](https://github.com/c4milo/colibri/actions/runs/45898056242), the competitors;
    [45898059688](https://github.com/c4milo/colibri/actions/runs/45898059688), the throughput;
    and [45898063826](https://github.com/c4milo/colibri/actions/runs/45898063826), the latency.
    They are the first charts that mark colibri's changes since the previous release (13u).
  - **Check:** `python3 bench/chart.py --test`, in `tools/ci.sh`, draws each chart from
    synthetic reports. At the redraw, nineteen mutations, each CAUGHT: the bars not ordered, or
    ordered the wrong way; the ratio inverted; one digit after the point under ten; a tie that
    ignores the spread; a better server not reported; a higher CPU time taken as better; a rate
    held without 95% reached, past the bound, or with an answer not 200; a floor drawn as a
    measured rate; the report's names kept; an input outside the chart read; colibri drawn
    alone; no dashed bound; the CPU part not named; the first sustained rate taken for the
    highest; no `1M` on the axis; and a throughput subtitle without the seconds of a load. Two
    mutations of the first charts left in 13q with the code they broke: the h3 stacks
    not named, and a throughput that counts answers not 200.
- **13n**, two inputs with a large response, which the owner asked for on 2026-11-19 to judge
  design §8 step 65: its output holds a third fewer bytes of a large body for each `send`. No
  input sent one before: each answer carried 8 bytes, and the POST routes answer "ok".
  - The test-only server takes `--body <octets>`, from 1 to `answer_body_len_max`, 1 MiB. It
    then answers every request with that many bytes of `answer_body_octets`, in place of
    `response_body`. It refuses the option with `--echo`, `--routes` or `--coded`, whose answers
    are their own.
  - `h2-large-many` and `h2-tls-large-many` run the server with `--body 262144` under h2-many's
    load, with 2,000 requests a round in place of 20,000, so a round sends 512 MiB. `report.py`
    takes that count as `--large-requests`, and requires each round of the two inputs to
    answer it.
  - Only colibri's servers serve them. A tree whose server's usage does not name `--body`, one
    from before this step, does not run them: `serves_colibri` reads the usage, as for 13l, and
    the report gives the input without a verdict.
  - **Check:** a test of `server_options.zig` requires `--body` to take from 1 byte to the
    most, and to refuse 0, one byte past the most, a word, no value, and each mode with an
    answer of its own. A test of `server_session_test.zig` requires an h11 answer under `--body`
    to carry the whole body and its `content-length` over several steps. A test of `report.py`
    requires the large input's own count, and refuses h2-many's for it.
  - Seven mutations, each CAUGHT: `--body` beside a mode that answers itself; a body of 0
    bytes; no body at the most; the fixed body in place of `--body`'s; the fixed
    `content-length`; and in `report.py`, the large input planned as h2-many, both ways.
  - The judge's first run, 44530085526, measured both inputs and then failed in `report.py`,
    which planned 20,000 requests for them. That run is why the count is an argument.
- **13o**, Go's servers among the competitors, which the owner asked for on 2026-11-19: Go's
  net/http and fasthttp, since the CPU chart of the README had no Go server but quic-go's.
  - `bench/competitors/nethttp/` is Go's own net/http server. It serves h11, h2 in cleartext with
    prior knowledge, and h2 or h11 by ALPN over TLS. `bench/competitors/fasthttp/` is fasthttp,
    pinned at v1.79.0 by its `go.mod` and `go.sum`, which serves h11 alone, in cleartext and over
    TLS. Each answers every request with 200, `text/plain; charset=utf-8` and `colibri\n`, as
    the other competitors do, with `GOMAXPROCS=1`.
  - `run_competitors.sh` builds each with `go build -trimpath`, and names the Go release and
    fasthttp's version in the report. Neither serves an h3 input, a route table's input or a
    large body's, and fasthttp serves the h11 inputs alone.
  - The README's charts call Go's servers `net/http` and `fasthttp`, and the latency run's chi
    `net/http + chi`, and `quic-go + chi` over h3: chi is a router on Go's net/http.
  - **Check:** each server answered curl with 200 and `colibri\n` over h11, over h2 in cleartext
    where it speaks h2, and over TLS, on macOS arm64 with Go 1.27.3.
- **13p**, the competitors at their latest versions, and Fastify among them, which the owner
  asked for on 2026-11-19. Ubuntu's nginx was 1.24.0 and its h2o 2.2.5, from 2018, and the owner
  found Fastify's throughput suspiciously low.
  - nginx comes from nginx.org's mainline packages, whose signing key `bench.yml` checks by its
    fingerprint. h2o is built with mruby from `H2O_COMMIT`, d3e43fcf of 2026-11-14, and the
    build is cached under the commit.
  - hyper's tokio goes to 1.54.1 and its aws-lc-rs to 1.19.0, axum to 0.8.9, and both build with
    Rust 1.100.0. chi goes to v5.5.0 and its quic-go to v0.65.0, Fastify to 5.12.8 on Node 26,
    http.zig to 1bb71ff1 with Zig 0.17.1, and quic-go's interop image to the digest of
    2026-11-19. hyper 1.12.0, rustls 0.23.46, quinn 0.11.12 and fasthttp v1.79.0 were the
    latest already.
  - Fastify joins the competitor run, so its CPU time a request is counted beside the others:
    without `--routes` it answers `GET /` with `colibri\n`.
  - **Check:** axum and hyper built with Rust 1.100.0, chi with quic-go v0.65.0, and http.zig
    with Zig 0.17.1. Fastify answered curl with 200 and `colibri\n` over h11 and h2, in
    cleartext and over TLS, on macOS arm64.
- **13q**, throughput at full load, which the owner asked for on 2026-11-19: the README's
  throughput chart, from the latency run, stopped near oha's own limit of about 80,000 to 95,000
  requests a second, where colibri's server used about half its core.
  - The owner refused a rate derived from CPU time alone, a model, and colibri's own client as
    the load, which a reader could doubt. The judge has 4 vCPUs, so the load keeps its two cores.
  - `bench/run.sh --throughput` loads each server with h2load, or wrk for h11, at full speed for
    10 s: 32 connections, which colibri's test-only server holds on its one worker, with 100
    streams on each h2 or h3 connection. `bench/run_throughput.sh` keeps the server's CPU time,
    from its threads' schedstat, and the load's wall time.
  - `bench/report_throughput.py` gives the median requests a second the load tool counted, and
    the server's busy share. Under 0.95 the load tool was the limit, and the chart marks the bar
    with ≥. It refuses a load that errored, timed out, got an answer outside 2xx, or failed more
    requests than were in flight when its time ran out.
  - **Check:** `python3 bench/report_throughput.py --test`, in `tools/ci.sh`, reads synthetic
    loads. Seven mutations, each CAUGHT: the warm-up counted; the limit inverted; a load cut at
    its end refused; an error allowed; an answer outside 2xx allowed; socket errors allowed; and
    the mean in place of the median. `bench/chart.py --test` reads a synthetic report too, and a
    floor drawn as a measured rate is CAUGHT.
- **13r**, axum on quinn among the h3 competitors, which the owner asked for on 2026-11-19. The
  CPU and throughput charts had quic-go alone over h3, and Rust's h3 stack was in the latency
  chart alone.
  - With `--h3`, `--competitors` and `--throughput` measure the axum program of 13f on the h3
    inputs that quic-go serves, with `--www` and `--h3`: axum's router over the h3 crate on quinn.
    It reads the file of each request from the directory colibri's UDP server reads.
  - `run_competitors.sh` builds it with cargo, and the report names the versions of axum, h3 and
    quinn. The owner chose it over quiche, which the arm64 judge must build from source.
  - When the h3 panel holds axum, each chart's subtitle says that axum serves h3 through quinn and
    the h3 crate.
  - axum's h3 server read no request stream to its end. So quinn stopped each one with
    STOP_SENDING and code 0, where RFC 9114 §4.1 asks for H3_NO_ERROR. h2load counts such a
    request as failed, and oha does not, so the latency runs before 13r did not show it. The
    first judge runs, 44573603371 and 44573622792, stopped when axum answered no request of
    h2load. The server now reads each request stream to its end, for the latency run too.
  - **Check:** `bench/chart.py --test` draws a synthetic h3 panel with axum. Four mutations, each
    CAUGHT: the line in every chart, in none, and left out of the CPU chart or the throughput
    chart. In a Debian container on macOS arm64, h2load counted axum's one answer as failed
    before the fix. After it, h2load counted 1 request of 1 and 896,100 of 896,100 in 5 s, each
    succeeded. The judge's three runs at `70f186c1` passed in both jobs. In job 1, axum on quinn
    took 11.5 µs a request over h3, 2.85 times colibri's, and served 118,520 requests a second, a
    core busy 0.98 of the time.
- **13s**, which side sets the latency, which the owner asked on 2026-11-19. Over h3, oha reached
  about 57,000 requests a second against colibri and 55,000 against axum. Under h2load the two
  serve 263,237 and 118,520 on one core, and their p99s rose together from 20,000 on. So the h3
  panel of the latency chart may measure oha and not the servers.
  - The owner chose to measure it. In each load of `--latency`, `run_latency.sh` reads each thread
    of the server and of oha from its schedstat, 1 s after the load starts and 1 s before it ends.
    It also reads the UDP datagrams the kernel dropped from `/proc/net/snmp` before and after the
    load. `bench/run_latency_busy.sh` holds the two reads, since `run_latency.sh` passes 500 lines
    with them.
  - `report_latency.py` gives four figures for each load: the share of that time the server's
    threads ran, the cores oha's threads ran together, the share its busiest thread ran, and the
    drops. `bench/chart.py` reads the wider rows.
  - **Check:** `python3 bench/report_latency.py --test` reads synthetic loads. Seven mutations,
    each CAUGHT: the counts before the middle ignored, the busiest thread taken as the sum, the
    length of the middle ignored, the drops ignored, a thread that started inside the middle left
    out, the warm-up's figures read, and no figures read. `bench/chart.py --test` draws the same
    chart from the wider rows, and a parser that drops them is CAUGHT.
  - **What it found.** Run [44598317114](https://github.com/c4milo/colibri/actions/runs/44598317114)
    measured the branch on the judge, and both jobs agree. oha was not the limit: its busiest
    thread ran at most 0.79 of the time over h3, and 0.72 over h2. Over h3 the servers set the
    p99. At 40,000 requests a second, colibri's core was busy 0.62, 15.5 µs a request, and
    axum's 0.75 and 0.77. Over h2 colibri's core was busy 0.18 and 0.19, and over h2-tls 0.20
    and 0.22. Near 55,000 requests a second axum's core runs full, 0.99, and colibri's 0.84 and
    0.87, where the 32 requests in flight hold the rest. No UDP datagram was dropped.
  - So no point of the chart needs a mark for oha, and the chart has none. With 160 requests in
    flight, colibri's h3 costs 4.0 µs a request: an h3 request at 32 in flight costs almost four
    times as much. https://github.com/c4milo/colibri/issues/139 tracks that cost.
  - For that issue the owner asked on 2026-11-19 for the datagrams of each request. The report
    now gives the UDP datagrams the kernel took in and sent for each answered request, from
    `/proc/net/snmp`. They count every socket, the server's and oha's together, and a send of
    segments counts once, so they compare servers under the same oha and the same protocol.
    Three mutations, each CAUGHT: the two counts swapped, a count not divided by the answers,
    and the counts not read.
  - Run [44619128899](https://github.com/c4milo/colibri/actions/runs/44619128899) counted them,
    and both jobs agree. At 2,000 requests a second an h3 request took 3.88 to 3.93 datagrams
    with colibri, 2.60 with axum on quinn and 3.87 with quic-go. At 40,000 it took 2.29 to 2.39
    with colibri and 2.11 to 2.13 with axum. The h2 loads counted 0.00, so no other traffic adds
    to the count. https://github.com/c4milo/colibri/issues/139 follows the extra datagrams.
- **13t**, an input with coded responses, which the owner asked for on 2026-11-19 to judge
  design §8 step 67. No input coded a response before, so no number showed that `take` filled
  299,768 bytes of each encoder in ReleaseSafe.
  - `h2-coded-many` runs the server with `--coded` under h2-many's load. Each request carries
    `accept-encoding: gzip`, so each answer of 8 bytes goes out in gzip, as 28 bytes.
  - After the warm-up, `codes` sends one request that accepts gzip. The run fails when the
    answer's Content-Encoding does not name gzip (RFC 9110 §8.4). `codes` and the other checks
    of a server before its measurement move to `bench/run_ready.sh`, because `bench/run.sh`
    passed 500 lines.
  - Only colibri's servers serve it. A tree whose server's usage does not name `--coded`, one
    from before design §8 step 17e, does not run it.
  - The server's pool holds 4 encoders, and a response holds its encoder until it writes its
    last byte. Under 16 connections of 10 streams each, all 20,000 answers of a round still went
    out coded: h2load counted 560,000 bytes of data, 28 for each answer. That ran in an ubuntu
    24.04 container on the laptop.
  - **Check:** in that container, `codes` passed against the server with `--coded` and failed
    against the server without it. The judge's first run with the input, 44661604715, is
    recorded under step 67: `codes` passed for both trees in both jobs.
- **13u**, each release's changes marked on the README's charts, which the owner asked for on
  2026-11-26, as connect-zig's charts mark theirs.
  - `bench/chart.py` writes colibri's values beside each SVG, as `docs/images/<chart>.json`,
    with the CPU model, the run, the commit and the release that `--release` names. The file
    carries a version, and a reader refuses a file of another version.
  - With `--previous <file>`, the same chart's file of the previous release, each bar chart
    draws a dashed line across colibri's bar at the previous value. After the bar's label it
    gives ▲ and the change when the value is 5% or more better, and ▼ when it is that much
    worse (`bench/chart_change.py`). The latency chart marks colibri's highest sustained rate
    after each panel's name. A note at each chart's foot says what the marks compare.
  - A run on another CPU model compares nothing, and the note says so. A new kernel on the
    same CPU model still compares.
  - The redraw of a release passes the files that the commit before it holds, the previous
    release's values. v0.21.0's files come from its three runs' reports, 288, 291 and 292.
  - **Check:** `python3 bench/chart.py --test`, in `tools/ci.sh`. Ten mutations, each CAUGHT: a
    threshold of 6%; a cost that rises taken as better; a run on another CPU model compared; a
    new kernel taken for another CPU model; no dashed line; the arrows swapped; a file of
    another version read; the latency chart's first sustained rate taken for its highest; a
    mark on another server's bar; and none on colibri's.


  **Check:** the judge's report gives colibri's ratio to each competitor on each input it
  serves, from a run with `competitors` and `h11` set. `report.py --test` holds the report to
  wrk's counts and errors, to the tool and the version each input takes, to the close each
  `-one` h11 input asks for, and to a competitor that serves some inputs alone.

*Medium.*

**13a, 2026-09-30.** `bench/run.sh` builds the test-only h2 server in ReleaseSafe, pins it and
h2load to cores of their own, and counts the server's instructions, cycles, CPU time and system
calls per request and per connection with `perf stat`. `bench/report.py` gives each input's
median and spread over five rounds after a warm-up it discards, and the ratio of the change to
the base, losses first; a loss past the noise fails the run. `.github/workflows/bench.yml` runs
both in two jobs on the `ubuntu-24.04-arm` runner: a Neoverse-N2 with 4 cores, Linux
6.17.0-1022-azure and perf 6.17.13.

What each check printed:
- The floor. In five jobs of a tree against itself, no ratio of instructions per unit moved from
  1 by more than 0.13%, and the owner set the floor at 0.5%. `docs/performance.md` lists the
  runs.
- The mutant: 150 iterations of a four-instruction loop in the server's `write_head`, 600
  instructions per response head by the disassembly, on a branch deleted after
  [run 36732471944](https://github.com/c4milo/colibri/actions/runs/36732471944). In both jobs
  h2-many lost at 1.0155 and h2-tls-many at 1.0071 and 1.0069, and each job failed. User
  instructions per request on h2-many rose by 604.1 in each job. h2-one and h2-tls-one stayed
  within the noise, as a cost of 0.2% and 0.001% of theirs should: **CAUGHT**.
- `python3 bench/report.py --test`, which `tools/ci.sh` runs: 12 tests, and 17 mutations of the
  report, each **CAUGHT**. A server that never listens stops the run at the readiness probe,
  and a probe that trusts h2load's exit status lets it through: **CAUGHT**.
- The first runs found three defects, each fixed on main: the probe (9ee28cb), perf 6.17's
  task-clock unit (9ee28cb and 55de1f4), and compiler_rt's `memset` in the timed programs
  (4267c63). [Run 36727035651](https://github.com/c4milo/colibri/actions/runs/36727035651)
  judged the last in both jobs: h2-one ran 0.355 of its instructions, h2-many 0.847,
  h2-tls-many 0.924 and h2-tls-one 0.989.
- With it, [run 36727047216](https://github.com/c4milo/colibri/actions/runs/36727047216)
  counted 39,040 instructions per request on h2-many, 86,084 on h2-tls-many, about 304,600 per
  connection on h2-one and 55.57 million on h2-tls-one.

**13b, 2026-09-30.** `bench/memory.zig` measures each struct a caller holds for one connection
with `@sizeOf`, and `zig build bench-memory` prints the table for the objects the build targets,
under a heading that names chapulin's `AES` value. x86-64 and arm64 build `AES=runtime` (decision
97 as amended), so `docs/performance.md` holds one table, and `zig build test` checks it.

What each check printed, on macOS arm64:
- `zig build test-bench`, and `zig build test-bench -Dcpu=generic`: 1 of 1 test each.
  `zig build bench-memory` for `x86_64-macos`, run under Rosetta with `-Dcpu=znver3` and with
  `-Dcpu=x86_64`, printed the same table.
- 2 mutations, each **CAUGHT**: a number changed in the table, and 8 bytes added to
  `h11.connection.Connection`.
- The largest structs: `server.Connection` holds 306,272 bytes and `server.QuicConnection`
  717,520, the latter without the receive pool its caller passes, whose default holds 1,505,288.

**13c, 2026-10-01.** `bench/run.sh --competitors` measures nginx 1.24.0 and h2o 2.2.5, from the
runner's Ubuntu 24.04 packages and built with OpenSSL 3.0.13, in turns with colibri's server over
the four inputs. Each answers the same eight bytes from memory, with one worker on the server's
core, and each presents the same P-256 identity and runs TLS_AES_256_GCM_SHA384 over X25519.
`docs/performance.md` says how each is set up.

[Run 36851113101](https://github.com/c4milo/colibri/actions/runs/36851113101), on cf7bcd2,
printed these medians per request or per connection. Its two jobs agree within 0.6% on every
instructions figure and within 5% on every cycles figure; this is the first job:

| Input | Instructions: colibri | h2o | nginx | Cycles: colibri | h2o | nginx |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| h2-many | 39,040 | 34,340 | 46,184 | 11,169 | 15,569 | 28,606 |
| h2-tls-many | 85,507 | 37,699 | 41,522 | 29,934 | 20,683 | 21,680 |
| h2-one | 304,215 | 143,544 | 141,706 | 171,778 | 104,541 | 98,323 |
| h2-tls-one | 55,569,416 | 2,353,014 | 2,589,572 | 22,410,663 | 1,461,011 | 1,381,869 |

Against decision 31's expectations:
- Many requests on one connection: colibri makes 0.04 system calls per request, where h2o makes
  1.2 and nginx 2.1. It takes the fewest cycles of the three, 0.72 of h2o's and 0.39 of nginx's,
  and fewer instructions than nginx, 0.85 of its count, but more than h2o, 1.14.
- A cleartext connection, where decision 31 expects colibri to win: colibri loses. It costs 2.1
  times the instructions of either competitor and 1.6 to 1.7 times the cycles, and 5 to 9 times
  their user instructions.
- TLS, where decision 31 expects colibri to match, because every competitor calls the same
  asymmetric crypto: colibri loses. A handshake costs 21 to 24 times the instructions of either
  competitor and 15 to 16 times the cycles. A request over TLS costs 2.1 to 2.3 times the
  instructions and 1.4 times the cycles. Both are chapulin's work (decision 94), not OpenSSL's.
- The first competitors run,
  [36813252981](https://github.com/c4milo/colibri/actions/runs/36813252981), failed before it
  measured: h2o, started by the runner's own user, refused the `user` line a container needs.
  cf7bcd2 keeps that line for root alone.

**13g, 2026-10-18.** `bench/run.sh --competitors --h11` measures hyper and http.zig beside
nginx and h2o, over the four h2 inputs and the four h11 ones, which wrk sends. hyper runs 1.12.0
on tokio 1.53.3 and rustls 0.23.46 over aws-lc-rs 1.18.2, built with Rust 1.99.0. http.zig runs
at e8272bfd, built with Zig 0.17.0. Every TLS input ran TLS_AES_256_GCM_SHA384 over X25519.

[Run 39100192931](https://github.com/c4milo/colibri/actions/runs/39100192931), on 13d6a5a,
printed these medians per request (`-many`) or per connection (`-one`). Its two jobs agree
within 3.1% on every ratio, and within 1.2% on all but three; this is the first job's
instructions, kernel and user together:

| Input | colibri | nginx | h2o | hyper | http.zig |
| --- | ---: | ---: | ---: | ---: | ---: |
| h2-many | 14,648 | 46,117 | 34,347 | 27,460 | — |
| h2-tls-many | 18,576 | 40,674 | 37,699 | 29,058 | — |
| h2-one | 146,993 | 142,385 | 143,490 | 213,707 | — |
| h2-tls-one | 1,949,599 | 2,590,653 | 2,357,626 | 1,038,078 | — |
| h11-many | 37,601 | 28,418 | 52,429 | 27,290 | 73,882 |
| h11-tls-many | 52,738 | 51,571 | 75,059 | 32,959 | — |
| h11-one | 111,667 | 72,184 | 102,156 | 89,822 | 100,503 |
| h11-tls-one | 1,822,806 | 2,141,032 | 2,130,477 | 788,359 | — |

http.zig serves no TLS and no h2, so it has no number there. Against decision 31's
expectations:
- Many requests on one connection over h2: colibri takes the fewest instructions of the five,
  0.32 to 0.53 of each competitor's in cleartext and 0.44 to 0.64 over TLS.
- An h2 connection in cleartext: colibri matches nginx and h2o, at 1.02 to 1.03 of theirs, and
  takes 0.69 of hyper's.
- TLS handshakes, where decision 31 expects colibri to match: colibri takes 0.75 of nginx's
  instructions on h2-tls-one and 0.83 of h2o's, and 0.85 of either's on h11-tls-one. 13c
  measured 21 to 24 times theirs on chapulin before 0.2.0. hyper takes about half of colibri's:
  1.88 times on h2-tls-one and 2.31 times on h11-tls-one, where rustls on aws-lc-rs runs the
  handshake.
- h11 is where colibri loses most. Many requests take 1.32 times nginx's instructions and 1.38
  times hyper's, though 0.72 of h2o's and 0.51 of http.zig's. A connection with one request
  takes 1.09 to 1.55 times every competitor's. Over TLS with many requests, colibri matches
  nginx and takes 1.60 times hyper's. colibri's h11 path is the next performance target.

**13d, 2026-10-20.** On 2026-10-18 the owner asked for the judge by protocol. The owner ruled
for h11 on wrk, h2 on Ubuntu's h2load, and h3 on `h2load --alpn-list=h3` from `tools/h3load/`'s
image.
quic-go is the one h3 competitor. quiche's images are x86-64 alone, so the arm64 judge cannot run
it yet. Ubuntu's nginx 1.24 and h2o 2.2.5 serve no h3, and hyper and http.zig have none.

`bench/run.sh --h3` adds h3-many and h3-one against the test-only UDP server in its `h3` mode.
Each h3 request asks for a file, because quic-go's server answers from files alone. The report
prints one block for each protocol, in the order h11, h2, h3, and names the client of each.

[Run 39426505696](https://github.com/c4milo/colibri/actions/runs/39426505696), on 34fb00b, ran
`--competitors --h11 --h3` in 22 minutes. Its two jobs give the same verdict on each of the 28
ratios, and agree within 3% on each. The medians are the first job's instructions per request
(`-many`) or per connection (`-one`), kernel and user together:

| Input | colibri | nginx | h2o | hyper | http.zig | quic-go |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| h11-many | 36,638 | 28,580 | 52,475 | 27,463 | 74,054 | — |
| h11-tls-many | 51,054 | 51,517 | 75,117 | 33,011 | — | — |
| h11-one | 98,207 | 72,119 | 102,162 | 89,907 | 103,090 | — |
| h11-tls-one | 1,810,280 | 2,140,834 | 2,128,399 | 787,721 | — | — |
| h2-many | 14,637 | 46,137 | 34,356 | 27,470 | — | — |
| h2-tls-many | 18,347 | 41,434 | 37,737 | 29,045 | — | — |
| h2-one | 144,484 | 141,603 | 143,923 | 204,963 | — | — |
| h2-tls-one | 1,943,613 | 2,589,974 | 2,353,865 | 1,033,615 | — | — |
| h3-many | 148,595 | — | — | — | — | 213,717 |
| h3-one | 3,589,765 | — | — | — | — | 3,278,417 |

What the run shows:
- h3, many requests on a connection: colibri takes 0.69 to 0.70 of quic-go's instructions.
- h3, one request on each connection: colibri takes 1.09 to 1.10 times quic-go's instructions.
  It still completes 2,079 connections a second of one core, against quic-go's 1,527, because
  it takes fewer cycles.
- h3-many costs about ten times h2-many's instructions a request. Each h3 request costs 5.08
  system calls, where an h2 request costs 0.07. This is the next h3 cost to profile.
- h11, after the three changes of 7496cdc..ab1e2164: h11-one now takes 0.95 to 0.96 of h2o's
  and http.zig's instructions. It takes 1.08 to 1.09 times hyper's, and 1.35 to 1.36 times
  nginx's. h11-many takes 1.28 to 1.36 times nginx's and hyper's.
- h2: each verdict is the one 13g recorded.

**The competitors again, 2026-10-27.** The owner asked where colibri stands after the changes
since 13d. [Run 40615818807](https://github.com/c4milo/colibri/actions/runs/40615818807), on
1681310f, ran `--competitors --h11 --h3` in 22 minutes, with the competitors 13d ran. Its two
jobs give the same verdict on each of the 28 ratios, and agree within 2% on each. The medians
are the first job's, counted as 13d counts them:

| Input | colibri | nginx | h2o | hyper | http.zig | quic-go |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| h11-many | 32,625 | 28,500 | 52,489 | 27,366 | 75,717 | — |
| h11-tls-many | 41,097 | 51,527 | 75,025 | 32,977 | — | — |
| h11-one | 97,191 | 71,872 | 101,986 | 89,806 | 103,348 | — |
| h11-tls-one | 942,030 | 2,141,186 | 2,128,927 | 787,913 | — | — |
| h2-many | 13,679 | 45,961 | 34,363 | 27,474 | — | — |
| h2-tls-many | 16,121 | 41,682 | 37,715 | 29,055 | — | — |
| h2-one | 136,238 | 140,831 | 143,881 | 205,899 | — | — |
| h2-tls-one | 1,030,725 | 2,589,097 | 2,354,043 | 1,033,421 | — | — |
| h3-many | 146,740 | — | — | — | — | 212,547 |
| h3-one | 1,474,466 | — | — | — | — | 3,295,962 |

What the run shows, against 13d:
- A TLS handshake costs about half of what it cost. h11-tls-one, h2-tls-one and h3-one fall 48%,
  47% and 59%. colibri now takes 0.40 to 0.44 of nginx's and h2o's instructions. It matches
  hyper on h2-tls-one and takes 1.20 times hyper's on h11-tls-one. The run does not show which
  changes made the fall.
- h3-one now takes 0.45 of quic-go's instructions, where 13d measured 1.09 to 1.10 times. It
  completes 3,578 connections a second of one core, against quic-go's 1,463. h3-many stays at
  0.69 of quic-go's.
- h2-one now takes 0.97 of nginx's instructions and 0.95 of h2o's, where 13d measured 1.02 to
  1.03 times. The other h2 verdicts are 13d's.
- h11 is still where colibri loses. h11-many fell 11%, to 1.14 times nginx's instructions and
  1.19 times hyper's. h11-tls-many fell 20%, and now
  takes 0.80 of nginx's, and 1.25 times hyper's. h11-one stays at 1.35 times nginx's and 1.08
  times hyper's.

**The competitors on 0.9.0, 2026-10-29.** The owner asked where 0.9.0 stands. [Run
40889497528](https://github.com/c4milo/colibri/actions/runs/40889497528), on the tag v0.9.0
(`bf4fe21f`), ran `--competitors --h11 --h3` in 21 minutes. Its two jobs give the same verdict
on 27 of the 28 ratios. On h11-one against h2o, job 1 wins and job 2 stays within the noise.
Each run measures on its own machine, so only the ratios compare across runs. The ratios that
moved, job 1 and then job 2, against the run of 2026-10-27:
- h11-many takes 1.16 times hyper's instructions in both jobs, where it took 1.19. It takes
  1.12 times nginx's, where it took 1.14.
- h11-one takes 1.28 and 1.32 times nginx's, where it took 1.35.
- h11-tls-many takes 1.21 times hyper's in both jobs, where it took 1.25.
- h2-tls-one takes 0.98 of hyper's, a win, where it was within the noise.
- h3-many takes 0.66 and 0.65 of quic-go's, where it took 0.69.

h11 is still where colibri loses, to nginx and hyper alone. The h11 head scan and the 64-bit
quota came after the run of 2026-10-27.

**The competitors on 0.10.0, 2026-10-30.** The owner asked where 0.10.0 stands. [Run
41043519893](https://github.com/c4milo/colibri/actions/runs/41043519893), on the tag v0.10.0
(`a23be1b2`), ran `--competitors --h11 --h3`. Its two jobs give the same verdict on 27 of the 28
ratios. On h11-one against hyper, job 1 stays within the noise and job 2 wins. The ratios that
moved, job 1 and then job 2, against the run on 0.9.0:
- h3-many takes 0.52 of quic-go's instructions in both jobs, where it took 0.66 and 0.65.
- h2-one takes 0.91 and 0.92 of nginx's, and 0.92 and 0.93 of h2o's.
- h11-one takes 1.23 and 1.15 times nginx's, where it took 1.28 and 1.32. It takes 1.01 and
  0.95 of hyper's.
- h11-tls-one takes 1.16 times hyper's in both jobs.

h11 is still where colibri loses, to nginx and hyper alone: 1.12 to 1.16 times theirs with many
requests, and 1.20 times hyper's over TLS.

**The competitors after step 29d.19, 2026-11-08.** The owner asked how colibri compares now.
[Run 42532324158](https://github.com/c4milo/colibri/actions/runs/42532324158), on main
`29c407a4`, ran `--competitors --h11 --h3`. Its two jobs give the same verdict on each of the 28
ratios. The judge now runs Linux 7.0.0-1017-azure. Instructions a request on the `-many` inputs
and a connection on the `-one` inputs, from job 1:

| Input | colibri | nginx | h2o | hyper | http.zig | quic-go |
|---|---|---|---|---|---|---|
| h3-many | 28,682 | — | — | — | — | 218,698 |
| h3-one | 1,328,069 | — | — | — | — | 3,342,483 |

- h3-many takes 0.13 of quic-go's instructions in both jobs, where it took 0.52 on 0.10.0.
  Step 29d took colibri from 146,740 a request on 2026-10-27 to 28,682, and quic-go's count
  stayed near 215,000.
- h3-one takes 0.40 of quic-go's. It completes 3,684 and 3,907 connections a second of one
  core, against quic-go's 1,306 and 1,533.
- Every h2 ratio wins, as on 0.10.0: from 0.26 of nginx's on h2-many to 0.96 of hyper's on
  h2-tls-one.
- h11 still loses to nginx and hyper alone: 1.11 and 1.12 times nginx's and 1.16 times
  hyper's on h11-many, 1.20 and 1.21 times nginx's on h11-one, and 1.16 to 1.20 times hyper's
  over TLS. It wins against h2o and http.zig on each h11 input.

[Run 42532331627](https://github.com/c4milo/colibri/actions/runs/42532331627) measured the
latency at fixed rates on the same commit, and docs/performance.md holds it as the new baseline.
Each server's highest rate under a p99 of 10 ms did not change. Over h3 at 40,000 req/s,
colibri's p99 was 15.51 ms and 15.30 ms, against axum's 22.86 ms and 18.61 ms.

**The network, waits and bulk runs after step 29d.19, 2026-11-09.** The owner asked for the
other latency runs too. Each measured main `5b858fe3` on the judge, on Linux 7.0.0-1017-azure,
in two jobs. Each pair below gives job 1, then job 2. Step 29d cut the server's instructions,
and none of these runs is bound by them, so each agrees with its last record.

- **`network`**, [run 42558149617](https://github.com/c4milo/colibri/actions/runs/42558149617),
  5 rounds. The p99 over h3 at 4,000 req/s, in ms:

  | Profile | colibri (CUBIC) | colibri-bbr | chi (quic-go) |
  | --- | --- | --- | --- |
  | `clean` | 0.32 and 0.33 | 0.32 and 0.32 | 0.66 and 0.71 |
  | `far` | 59.88 and 60.02 | 64.82 and 64.56 | 65.00 and 66.29 |
  | `lossy` | 109.00 and 107.71 | 105.29 and 106.59 | 106.93 and 106.96 |
  | `mobile` | 2,041 and 2,001 | 1,939 and 1,806 | 2,002 and 1,860 |

  On `mobile` no h3 server reached 4,000 req/s: colibri reached 3,220 and 3,231, and chi 3,200
  and 3,268. Over h2-tls on `mobile`, colibri's p99 was 593 ms and 649 ms, and chi's 4,126 ms
  and 4,130 ms.
- **`waits`**, [run 42558165516](https://github.com/c4milo/colibri/actions/runs/42558165516),
  5 rounds. Neither server waited for its core: each delay p99 was 0.000 ms. At 80,000 req/s
  colibri ran about 15,000 times a second, and a run took 0.016 to 0.024 ms at its p50.
  - h2 at 40,000 req/s: colibri's p99 was 1.19 ms and 1.33 ms, and axum's 1.86 ms and 2.01 ms.
  - h2-tls at 40,000 req/s: colibri's p99 was 2.72 ms and 2.97 ms, and axum's 2.34 ms and
    3.06 ms.
  - The two jobs differ at 80,000 req/s. Over h2, colibri's p99 was 12.45 ms and 28.30 ms, and
    axum's 76.30 ms and 640.51 ms. Over h2-tls, colibri's was 25.92 ms and 246.52 ms, and
    axum's 22.98 ms and 29.17 ms. In job 2, colibri's rounds over h2-tls went from 62.77 ms to
    548.46 ms. No run has measured the cause.
- **`bulk`**, [run 42575264322](https://github.com/c4milo/colibri/actions/runs/42575264322),
  3 rounds. A first run at 5 rounds,
  [42558157711](https://github.com/c4milo/colibri/actions/runs/42558157711), passed the job's
  limit of 180 minutes in its fifth round and left no report. Goodput in Mbit/s for 1
  connection, and the p99 of the GETs beside it:

  | Path | colibri (CUBIC) | colibri-bbr | colibri-newreno | chi (quic-go) | ngtcp2 |
  | --- | --- | --- | --- | --- | --- |
  | 20 Mbit/s, 25 ms | 17.34 and 17.34; 127 ms | 17.34 and 17.34; 105 and 106 ms | 17.34 and 17.34; 127 ms | 17.34 and 17.34; 232 ms | 16.78 and 16.78; 116 and 118 ms |
  | the same, 1% loss | 2.24 and 2.24; 129 and 132 ms | 15.10 and 13.98; 133 and 179 ms | 2.24 and 1.68; 178 ms | 3.36 and 3.36; 134 and 179 ms | 13.42 and 11.18; 182 and 192 ms |

  Through one bottleneck with 1 connection each, CUBIC took 0.62 of the goodput with no loss
  in both jobs, and BBRv3 took 0.86 and 0.89 with 1% loss. CUBIC at 1% loss still gets less
  than quic-go, which [#123](https://github.com/c4milo/colibri/issues/123) tracks.

**Main against v0.15.0, 2026-11-11.** The owner asked whether steps 44, 46, 47 and 48 made an
input slower. [Run 43070881619](https://github.com/c4milo/colibri/actions/runs/43070881619)
judged main `14ae68a9` against `29c407a4`, with `h11` and `h3` at 10 rounds. Its two jobs give
the same verdict on each input. Three earlier attempts measured nothing: the runners could not
resolve Ubuntu's package servers.

| Input | Main / v0.15.0, job 1 and job 2 | Verdict |
| --- | --- | --- |
| h11-tls-one | 0.839 and 0.841 | wins |
| h2-tls-one | 1.025 and 1.025 | loses |
| h11-one, user instructions | 1.022 and 1.021 | loses |
| h2-many, h2-one, h2-routes-many, h2-tls-many | 1.001 to 1.006 | within the noise |
| h3-many, h3-one, h3-bbr-many, h3-bbr-one | 0.995 to 1.001 | within the noise |
| h11-many, h11-tls-many | 1.007 and 1.008 | within the noise |

- h11-tls-one wins because wrk resumes its sessions (step 48): 937,677 and 940,799
  instructions a connection became 786,422 and 790,889.
- h2-tls-one loses by step 48. h2load resumes no session, so the server seals and sends tickets
  that the client never offers: 1,030,335 and 1,031,745 instructions a connection became
  1,056,089 and 1,057,491, with 1.5 more system calls. The same input took 1,030,781 on
  `83d58c09`, where the bench passed no `--seconds`. The owner ruled on 2026-11-11 to accept
  this cost: tickets stay on by default.
- h11-one loses by its user instructions, the measure of the h11 admission rule: 19,845 and
  19,882 a connection became 20,277 and 20,296. Its total is within the noise. Step 48 did not
  cause it: main `53866d8f` took 20,298 and 20,293 before that step
  ([run 42967640462](https://github.com/c4milo/colibri/actions/runs/42967640462)). So the cost
  came with step 44, 46 or 47.
- Callgrind split it on a laptop, with numbers that are never published. The test-only server of
  `29c407a4` and of `2921c194` ran in an aarch64 Linux container, under wrk's 16 connections
  with `Connection: close` for 20 s, and only that load was counted. A connection took 20,574
  instructions on v0.15.0 and 21,120 on main, at the same calls of each function:
  - About 320 are Rotor 0.10.0's, which step 44 pinned in place of 0.9.0. `Tables.submit`
    costs 19 more a call, the finish list 54 more a call, and the tick is split in two.
  - About 220 are colibri's, from step 47: `connection_close.owes_half_close`, 103 in 3 calls,
    `connection_close.staged`, 36, and 60 more in `read_protocol` at the same 7 calls.
  - The HTTP API session's bisect, by the same probe at six commits, gives the same two parts.
    v0.15.2 costs nothing, so step 46 is clear. Step 47's three fixes, `0b6d8c32`, `ee382efa`
    and `67d208e8`, add about 300 in roughly equal parts, and the pin of Rotor 0.10.0,
    `205dce5e`, adds about 400.
  - Docker refuses io_uring, so Rotor ran its epoll backend there. The judge runs io_uring,
    which shares the tables part alone. The HTTP API session and Rotor's session have the
    numbers.
  - The owner ruled on 2026-11-11 to accept the cost with no trim. Step 47's part is the cost
    that decision 160 chose. A single check of the half-close for each connection would save
    about 70 instructions, under h11-one's noise of about 0.5%. Rotor's part stays with Rotor's
    session.
  - Rotor 0.11.0 answers its part, and main pins it since `6dcd2d6f` (2026-11-12). Rotor's
    decision 33 counts one connection on a plain loop, under cachegrind: 3,905 instructions on
    io_uring at 0.10.0 and 3,771 at 0.11.0, and 5,006 and 4,712 on epoll. The judge then
    measured `6dcd2d6f` against `7a8d33f2`, with the h11 inputs at 10 rounds
    ([run 43359971092](https://github.com/c4milo/colibri/actions/runs/43359971092)). Each h11
    and h2 input is within the noise. h11-one took 20,302 and 20,287 user instructions a
    connection before the pin, and 20,288 and 20,254 after it: 0.9993 and 0.9984. So the pin
    costs nothing, and h11-one gains 15 and 33 instructions, under its noise of 0.5%. Rotor's
    row runs one tick for each operation of one connection. The judge's load holds many
    connections at once, so one tick may serve several. No run measured that reading.
- The loop that the program hosts (step 44), the long streams (step 46) and the h3 path show
  no change.
