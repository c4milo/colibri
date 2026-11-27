# Decision 67: TLA+ specifications, checked by the TLC model checker, check the designs colibri's protocol decisions rule

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-23, and amended the same day: the runner lives in pepegrillo and the
models in `spec/tla/`. TLC is the fourth tool colibri takes from outside, beside chapulin,
pepegrillo and Rotor, and like them the library never links it.

The simulator runs colibri's code over seeds of random loss. Entries 64 to 66 each repaired a
loss pattern its seeds never produced: a network that drops every packet of ACK frames alone.
Random loss rarely drops every acknowledgment in a row. TLC explores every behavior of a
model, so it finds such a pattern at once. `spec/tla/probe_timeout/ProbeTimeout.tla` models
what the probes of a PTO carry. With PING probes, TLC finds a lost frame never sent again.
With entries 64 and 66, it finds every frame delivered.

`zig build tla` runs pepegrillo's `tla` tool, configured in `tools/tla.zig`. It fetches
`tla2tools.jar` from tlaplus's v1.7.4 release, the last one not marked prerelease, once into
pepegrillo's cache. Before each run it checks the jar against the SHA-256 `tools/tla.zig` pins,
because the release publishes none. Each configuration names the result TLC must find. One
that must find a violation shows the property can fail, as a mutation does for a test.
`tools/ci.sh` runs the check where a Java runtime is installed.

The amendment makes the runner and the layout the ones every project of the owner's shares.
pepegrillo (entry 36) holds the runner, so no project keeps a script of its own. Each model is
a directory of `spec/tla/`, and Lean proofs, when colibri has any, go in `spec/lean/`. The pin
stayed v1.7.4: tlaplus replaced its v1.8.0 prerelease jar on 2026-09-23, so a v1.8.0 pin taken
earlier no longer matched what its URL served.

A model is not the code. A specification states the design a decision rules, and the
simulator and the tests check that the code does what the design says.

Two alternatives were refused. Committing the jar puts a binary in the history for what a
pinned hash already fixes. Running the models by hand alone lets a specification fall out of
date with no one noticing.

Amended by the owner on 2026-11-05, with entry 47 as amended the same day, because the models
took 51 of the push job's 100 minutes. The nightly `tla` job checks every configuration of
every model, and runs the seven trace checks over every seed. The first ruling of that day
also kept a quick tier in `tools/ci.sh`: a small configuration of each model, and 8 seeds of
each trace run, only for the paths that changed. The second ruling below replaces that part.

Amended a second time by the owner on 2026-11-05. `tools/ci.sh` checks no model and runs no
trace check by default, and the push job runs no TLC. With `CI_TLA=all`, `tools/ci.sh` checks
every configuration and runs each trace check over every seed. It fails when no Java runtime
is installed, because a person asked for every TLC check. The ruling also amends entries 87,
104, 105 and 125. `tools/ci.sh` runs their trace checks only with `CI_TLA=all`, and the
nightly job runs them every night.

The owner allowed the quick tier and the selection by changed paths to stay if they cost
nothing by default, and asked for fewer parts. Neither is kept, because the push job was their
one caller:

- The quick tier needed four copies of a configuration with a smaller bound, and each copy
  must follow its original.
- The selection needed a table from each source path to the models and the trace runs that
  depend on it. That table must follow each moved file, and its first version missed the
  shared modules and the simulator files.

Cost: a change that breaks a model, or a trace check, fails the next nightly run and not its
push. Gain: the push job spends no time in TLC, and one job holds every TLC run.
