# http2-frame-test-case, as vendored

The h2 frame vectors of design §8 step 4 (decision 25), copied unmodified from
[github.com/http2jp/http2-frame-test-case](https://github.com/http2jp/http2-frame-test-case)
at commit `5c67db0d4d68e1fb7d3a241d6e01fc04d981f465` (2015-11-16), under the MIT license in
`LICENSE`: 34 cases, one JSON file each, a directory per frame type plus `error/`.

`tools/h2_frames.zig` parses every case's wire with the h2 frame reader, requires the fields the
case lists, writes each normal case back, parses the result and requires the same fields; for the
nine normal cases without padding it requires the same octets too, and for the three padded ones
(`data/normal.json`, `headers/priority.json`, `push_promise/normal.json`) it does not, because
the corpus's padding octets are not zero and colibri writes zeros (RFC 9113 §6.1). It requires
each error case to be refused with one of the codes it names; `zig build test` runs it
(decision 38). The JSON is read by that tool, which may allocate; the library never reads it.
