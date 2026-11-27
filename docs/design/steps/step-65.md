# Design §8 step 65: an output of one HEADERS and one DATA frame, refused, 2026-11-19

[Design §8, the build plan](../../design.md#8-build-plan)

[#137](https://github.com/c4milo/colibri/issues/137), decision 166 as amended. The owner asked to
try a server output sized for one frame of header block, which saves 16,375 bytes of each TCP slot,
and the judge refused it.
- **The trial.** `output_len` held two frames of 16,393 bytes, 32,786 in place of 49,161. The
  largest block h2 sends still fit an empty output, in a HEADERS frame and a CONTINUATION frame.
- **The tiny frames.** h2 cut a DATA frame at the room the output had left. With the smaller
  output, the deadline trace run's bodies went out in frames of 135 to 4,021 bytes, its seed 0
  ran out of drain rounds, and seed 0x11 held more than 48 frames in the output. The owner chose
  a floor: h2 cut no DATA frame at the room below `data_frame_len_min`, unless the room held the
  rest of the body. The model `ServerDeadlines.tla` took the same floor.
- **The checks of the trial.** The tests of `h2`, `server`, `sim-run` and the rest passed, four
  censuses of the simulator moved, and 11 mutations were CAUGHT. `tools/ci.sh` passed 32 of 32
  on the tree, `6437a0c4`.
- **The judge**, [run 44541453452](https://github.com/c4milo/colibri/actions/runs/44541453452),
  measured the trial against `7ed63b9a`, which holds step 13n's inputs. `h2-large-many` lost in
  both jobs, at 1.1164 and 1.1129 of the base's instructions: its user instructions went from
  119,077 to 146,980 for each response of 256 KiB, since each response took more passes. Its
  system calls did not move, 0.354 against 0.355 a request. `h2-tls-large-many` stayed within
  the noise, at 1.0156 and 1.0173, though its user instructions rose 4.6%. Every other input
  stayed within the noise. The first run, 44527800392, before step 13n, had no input with a
  large body, and found none losing.
- **What stays.** The output stays 49,161 bytes, and no floor on the room lands. The branch
  `one-frame-65b` keeps the trial.
