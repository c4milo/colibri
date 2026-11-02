## Why

<!-- The reason for the change. Name the issue as https://github.com/c4milo/colibri/issues/<n>. -->

## Checks

- [ ] `zig build test` passes.
- [ ] Each check I added or changed has a mutation result, `CAUGHT` or `NOT CAUGHT`, in the
      commit body or in the step's entry in `docs/design.md` §8.
- [ ] Each check that an RFC requires cites the RFC and the section on its line.
- [ ] Each commit is a Conventional Commit, and `zig build lint-commits` passes.
- [ ] I changed no named limit, no dependency and no edge of the module graph, or an issue
      approved the change first.
