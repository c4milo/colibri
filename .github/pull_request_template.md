## Why

<!-- The reason for the change. Name the issue as https://github.com/c4milo/colibri/issues/<n>. -->

## Checks

- [ ] `zig build test` passes.
- [ ] Each check I added or changed has a mutation result, `CAUGHT` or `NOT CAUGHT`, in the
      commit body or in the step's file in `docs/design/steps/`.
- [ ] Each check that an RFC requires cites the RFC and the section on its line.
- [ ] Each commit is a Conventional Commit, and `zig build lint-commits` passes.
- [ ] Each public name I added is on its root's list, with an example in `examples/` and an
      entry in `docs/usage.md`.
- [ ] I changed no named limit, no dependency and no edge of the module graph, or an issue
      approved the change first. No HTTP module gains an edge into `quic`.
- [ ] No commit message and no part of this description names an AI tool.
