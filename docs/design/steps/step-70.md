# Design §8 step 70: a router starts in place, 2026-11-23

[Design §8, the build plan](../../design.md#8-build-plan)

connect-zig asked for it on 2026-11-23, for its OTLP sink
([#148](https://github.com/c4milo/colibri/issues/148)).
- **The cost.** A program started its router with `.{}`, as README.md showed. The field
  `entries` defaults to `@splat(.{})`, so `.{}` copied the router's whole default value from a
  constant of the program's image, each entry's response, body and state memory too.
  connect-zig's sink holds 64 entries of 257 KiB bodies and 1 MiB of route state. Its image held a
  `.data.rel.ro` of 155 MB, and it took about 426 MiB when it started.
- **The change.** `Router.init(router: *Router)` writes each field of the router and of each
  entry to its default, one field at a time, by [decision 158](../../decisions/0158-colibris-public-api-follows-tigerstyle-first.md) ruling 1. It goes
  one field down into the body, the copy of the header, the held writers, the path parameters
  and the query. Outside Debug a field whose default is `undefined` takes no store, so no
  buffer is written ([decision 163](../../decisions/0163-the-routers-handlers-take-the-programs.md) as amended on 2026-11-15). A field that
  `router_pool_init.zig` holds no rule for fails the compile.
- `.{}` still compiles, so no dependent breaks. README.md, docs/usage.md, the examples, both
  consumers and the test servers start their routers with `init`.
- **New public name:** `Router.init`, for connect-zig's OTLP sink and for each program that
  places a router.
- **Tests.** The first fills a router with 0x55, calls `init`, and requires each field that a
  request reads first to hold its default. The second does the same outside Debug, and requires
  each buffer to still hold 0x55.
- **Check:** five mutations, each CAUGHT: `used` not written; `failing_body` not written; `init`
  as `.{}`; the body written whole; and a new field of an entry, which fails the compile.
  `zig build test-server` catches the first two, and `zig build test-server -Drelease` the next
  two.
- **Measured** on x86-64 Linux with Zig 0.16.0. The program is a ReleaseSafe build with one
  function route and 64 entries, each of 4,096 response bytes and 263,168 body bytes.
  `Router.memory_bytes` is 17,229,136.
  - With `.{}`: a `.data.rel.ro` of 17,234,184 bytes, an image of 34,942,080 bytes, and a
    largest resident set of 35,640 KiB.
  - With `init`: a `.data.rel.ro` of 9,384 bytes, an image of 17,721,160 bytes, and a
    largest resident set of 12,976 KiB.
  - The same program with no start of the router: 12,924 KiB.
