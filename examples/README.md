# Examples

Each file here is a complete program of the kind a project that depends on colibri writes. It
imports the library modules by the names a dependent uses, and runs a colibri client and a colibri
server against each other.

| Example | What it shows |
| --- | --- |
| [`h11_exchange.zig`](h11_exchange.zig) | An h11 client pipelines a GET and a PUT, and sends the PUT's body from its own buffer with `count_body`. The server reads one request at a time and answers each. |
| [`h2_exchange.zig`](h2_exchange.zig) | An h2 client and server exchange their prefaces and SETTINGS, and the server answers a GET with HEADERS and DATA. Each side runs the loop every h2 program runs: `receive` one frame at a time, then `write_pending`. |
| [`link.zig`](link.zig) | Not an example of colibri, but what the two above run over: the stand-in for a program's sockets. |

Run every example, or one:

```sh
zig build examples
zig build example-h2_exchange
```

`tools/ci.sh` runs them on every push, so an example that stops working fails CI.

## The link

colibri does no I/O, so a program brings its own sockets and its own event loop. These examples
bring [Rotor](https://github.com/c4milo/rotor)'s loop and no socket at all
([decision 96](../docs/decisions.md)):
- the client and the server each run on a Rotor loop of their own, in one process and on one
  thread;
- what one side sends is copied into the other side's queue in memory, and the sending loop posts
  the other a message saying how many octets arrived;
- the instant colibri takes is the one the side's loop read at its last tick.

A real program replaces `link.zig` with its own sockets. The colibri calls stay the same.

## What is still to come

Examples over TLS, QUIC and h3 need chapulin, which design §8 step 16 links into the library. The
test-only endpoints in [`src/testing/`](../src/testing/) already run every protocol over real
sockets and chapulin, and show a whole program today.
