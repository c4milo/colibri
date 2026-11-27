# Design §8 step 14: stdx's decoders, taken as a package

[Design §8, the build plan](../../design.md#8-build-plan)

The decoder of the `gzip` and `deflate` codings is stdx's ([decision 90](../../decisions/0090-the-compression-codecs-live-in-stdx.md)),
and its own design names the check that proves it: https://github.com/c4milo/stdx/issues/1, with
zlib and Wuffs as oracles and baselines.
**Check:** colibri pins a stdx commit whose gzip and deflate decoders have passed that check,
and CLAUDE.md lists stdx among the ruled dependencies. *Small.*

**Check passed, 2026-09-26.** stdx's issue 1 closed that day, with its decoders checked against
zlib and Wuffs. colibri pins stdx `b969898`, stdx's `main` then, whose CI passed, and CLAUDE.md
lists stdx among the library's two dependencies. `build/modules.zig` gives h11 stdx's `codec`,
`gzip` and `zlib` modules. stdx is not lazy in `build.zig.zon`, because the library imports it:
a project that depends on colibri fetches it too. stdx's build declares `-Drelease` rather than
`-Doptimize`, as colibri's does, so colibri passes it `release`. `zig build` and `zig build test`
pass with it.
