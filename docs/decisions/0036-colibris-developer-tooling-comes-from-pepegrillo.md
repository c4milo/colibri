# Decision 36: colibri's developer tooling comes from pepegrillo, a Zig package pinned by hash

[All decisions](../decisions.md) · Section: [Tooling](../decisions.md#tooling)

Ruled by the owner on 2026-09-16. The lint driver and its generic rules, the cognitive-complexity
scorer, the commit-message linter and the pre-push hook are in
[github.com/c4milo/pepegrillo](https://github.com/c4milo/pepegrillo). `build.zig.zon` names it by
URL and hash as a lazy dependency, and `build.zig` requests it only when colibri is the root build,
so a project that depends on colibri never fetches it. `tools/` keeps what is colibri's alone: the
configuration of each rule and the fixtures that pin it, the `module-graph` rule, and the graph
check. `.githooks/pre-push` is a copy of pepegrillo's hook, and `zig build test` compares the two
byte for byte. The library never imports pepegrillo.

Design §8 step 0 copied the tooling from another repository, and within a day the two copies
had drifted in naming, output format and logic. Four alternatives lost. Keeping the copies
meant fixing every defect twice. A vendored copy needs no network, but keeps a copy per
repository and a sync step per change. A git submodule needs `git submodule update --init` in
every clone and every worktree. A `.path` dependency resolves from the build root, so inside
`.claude/worktrees/` it points at the wrong directory.

Cost: the first build on a machine, and the first after a bump, needs the network to fetch
pepegrillo (`zig build --fetch` does it ahead), and Zig extracts it into `zig-pkg/`. A rule
change is a pepegrillo commit before it is a colibri one, and a bump must also copy the hook.
Gain: one copy of the tooling; the hash as the guard against an edited copy; and
`zig build --fork=<path>`, which builds this tree against an unpushed pepegrillo checkout.
