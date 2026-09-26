"""The corpus and the report of tools/http_garden.sh (docs/design.md §8 step 15d, decision 88).

It feeds the HTTP Garden's REPL from the outside and reads what the REPL prints, and it imports
none of the Garden's code, which is GPL-3.0: colibri only runs the Garden.

    driver.py commands <origin>...   the REPL commands for every case, on standard output
    driver.py report <origin>...     the REPL's output on standard input, the report on standard output

Every case is one HTTP/1.1 request stream, sent to colibri and to each origin, whose parses the
REPL compares pair by pair (`grid`). colibri is listed first, so the first row of each grid is
colibri against every other origin: a check where they agree, or an X where they differ. The
report names each case and the origins colibri differs from. A difference is not yet a defect:
each one is judged against RFC 9112 before it counts as colibri's.
"""

import pathlib
import re
import sys

repository_root = pathlib.Path(__file__).resolve().parents[2]

# The golden corpus's request streams: one request each, and streams a server reads in turn.
golden_directories = ["src/golden/h11_request", "src/golden/h11_server"]

# Shapes the golden corpus does not hold: request smuggling's usual suspects (RFC 9112 §11.2) and
# valid spellings a strict parser might refuse.
extra_cases = [
    ("te_tab", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:\tchunked\r\n\r\n0\r\n\r\n"),
    ("te_trailing_space", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked \r\n\r\n0\r\n\r\n"),
    ("te_uppercase", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: CHUNKED\r\n\r\n0\r\n\r\n"),
    ("te_identity_chunked", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: identity, chunked\r\n\r\n0\r\n\r\n"),
    ("te_empty_member", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: , chunked\r\n\r\n0\r\n\r\n"),
    ("cl_repeated_same", b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"),
    ("cl_list_same", b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 5\r\n\r\nhello"),
    ("cl_leading_zero", b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 05\r\n\r\nhello"),
    ("cl_hex", b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0x5\r\n\r\nhello"),
    ("cl_negative", b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n"),
    ("chunk_size_zeros", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0005\r\nhello\r\n0\r\n\r\n"),
    ("chunk_size_space", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5 \r\nhello\r\n0\r\n\r\n"),
    ("chunk_ext_quoted", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5;a=\"b;c\"\r\nhello\r\n0\r\n\r\n"),
    ("chunk_size_uppercase", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n"),
    ("trailer_lone_lf", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nT: v\n\r\n"),
    ("nul_in_value", b"GET / HTTP/1.1\r\nHost: a\r\nX: a\x00b\r\n\r\n"),
    ("space_in_name", b"GET / HTTP/1.1\r\nHost: a\r\nX Y: z\r\n\r\n"),
    ("empty_name", b"GET / HTTP/1.1\r\nHost: a\r\n: z\r\n\r\n"),
    ("method_lowercase", b"get / HTTP/1.1\r\nHost: a\r\n\r\n"),
    ("http_0_9", b"GET /\r\n"),
    ("absolute_form_other_host", b"GET http://a/ HTTP/1.1\r\nHost: b\r\n\r\n"),
    ("host_empty", b"GET / HTTP/1.1\r\nHost: \r\n\r\n"),
    ("host_port_empty", b"GET / HTTP/1.1\r\nHost: a:\r\n\r\n"),
    ("version_1_2", b"GET / HTTP/1.2\r\nHost: a\r\n\r\n"),
    ("pipelined_post_get", b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhiGET /b HTTP/1.1\r\nHost: a\r\n\r\n"),
    ("expect_continue", b"POST / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nhi"),
]


def cases() -> list[tuple[str, bytes]]:
    """Every case, in a fixed order: the golden streams by file name, then the extra shapes."""
    result = []
    for directory in golden_directories:
        for path in sorted((repository_root / directory).glob("*.bin")):
            result.append((path.stem, path.read_bytes()))
    return result + extra_cases


def repl_literal(octets: bytes) -> str:
    """A payload as the REPL reads it: quoted, every octet but letters and digits as \\xHH, which
    its unicode-escape decoding turns back into the octet and its lexer never splits."""
    return "'" + "".join(chr(b) if chr(b).isalnum() and b < 128 else f"\\x{b:02x}" for b in octets) + "'"


def commands(origins: list[str]) -> None:
    servers = " ".join(["colibri", *origins])
    for name, octets in cases():
        # `payload` with nothing after it prints the stream it holds: the case's name, as a marker.
        print(f"payload {repl_literal(name.encode())} | payload")
        print(f"payload {repl_literal(octets)} | fanout {servers} | grid {servers}")


ansi = re.compile(r"\x1b\[[0-9;]*m")
marker = re.compile(r"\[b'([A-Za-z0-9_]+)'\]")
# One cell of a grid row: a symbol in its colour, or a blank, then a space.
cell = re.compile(r"(?:\x1b\[([0-9;]*)m)?(.)(?:\x1b\[0m)? ")
# The colours the REPL gives a cell: the two parses differ, or one of them fails the Garden's own
# check against the RFCs, whichever server produced it. Agreement is green.
differs = "0;31"
invalid = "37;41"


def row_colours(raw: str) -> list[str]:
    """The colour of each cell of a grid row, left to right. A blank cell has none."""
    return [colour for colour, _ in cell.findall(raw.split("|", 1)[1])]


def report(origins: list[str]) -> int:
    """Reads the REPL's output and prints each case colibri disagrees on. Returns how many cases
    went uncompared."""
    case = None
    findings = []
    seen = 0
    for raw in sys.stdin:
        line = ansi.sub("", raw).replace("garden> ", "")
        if found := marker.search(line):
            case = found.group(1)
            continue
        # The grid's first row: colibri against itself, then against each origin in order.
        if case is not None and line.startswith("colibri") and "|" in line:
            colours = row_colours(raw)[1:]
            case_name, case = case, None
            if len(colours) != len(origins):
                continue
            seen += 1
            differing = [origin for origin, colour in zip(origins, colours) if colour == differs]
            failing = [origin for origin, colour in zip(origins, colours) if colour == invalid]
            if differing or failing:
                findings.append((case_name, differing, failing))
    print(f"http_garden: cases={len(cases())} compared={seen} origins={len(origins)} disagreements={len(findings)}")
    for name, differing, failing in findings:
        if differing:
            print(f"http_garden: {name}: colibri parses it differently from {len(differing)} of {len(origins)}: {' '.join(differing)}")
        if failing:
            print(f"http_garden: {name}: a parse fails the Garden's RFC check against {len(failing)} of {len(origins)}: {' '.join(failing)}")
    return len(cases()) - seen


def main() -> int:
    if len(sys.argv) < 3 or sys.argv[1] not in ("commands", "report"):
        print(__doc__, file=sys.stderr)
        return 2
    origins = sys.argv[2:]
    if sys.argv[1] == "commands":
        commands(origins)
        return 0
    # A case the REPL printed no grid for was not compared, which fails the run.
    return 1 if report(origins) != 0 else 0


if __name__ == "__main__":
    sys.exit(main())
