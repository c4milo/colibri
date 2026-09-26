"""The corpus and the report of tools/http_garden.sh (docs/design.md §8 step 15d, decision 88).

It feeds the HTTP Garden's REPL from the outside and reads what the REPL prints, and it imports
none of the Garden's code, which is GPL-3.0: colibri only runs the Garden.

    driver.py names                     every case's name, one a line
    driver.py case <name> <origin>...   the REPL commands for one case, on standard output
    driver.py report                    the REPL's output on standard input, the report on standard output

Every case is one HTTP/1.1 request stream, sent to colibri and to each origin, whose parses the
REPL compares pair by pair (`grid`). colibri is listed first, so the first row of each grid is
colibri against every other origin, and the rows' labels name the origins in order. The report
names each case and the origins colibri differs from. A difference is not yet a defect: each one
is judged against RFC 9112 before it counts as colibri's.
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


def case_commands(name: str, octets: bytes, origins: list[str]) -> None:
    servers = " ".join(["colibri", *origins])
    # `payload` with nothing after it prints the stream it holds: the case's name, as a marker.
    print(f"payload {repl_literal(name.encode())} | payload")
    print(f"payload {repl_literal(octets)} | fanout {servers} | grid {servers}")


ansi = re.compile(r"\x1b\[[0-9;]*m")
marker = re.compile(r"\[b'([A-Za-z0-9_]+)'\]")
# A grid row: the server's name, the padding, then the bar before the cells.
row = re.compile(r"^(\S+)\s*\|")
# One cell of a grid row: a symbol in its colour, or a blank, then a space.
cell = re.compile(r"(?:\x1b\[([0-9;]*)m)?(.)(?:\x1b\[0m)? ")
# The colours the REPL gives a cell: the two parses differ, or one of them fails the Garden's own
# check against the RFCs, whichever server produced it. Agreement is green.
differs = "0;31"
invalid = "37;41"


def row_colours(raw: str) -> list[str]:
    """The colour of each cell of a grid row, left to right. A blank cell has none."""
    return [colour for colour, _ in cell.findall(raw.split("|", 1)[1])]


def grids(lines) -> dict[str, list[tuple[str, str]]]:
    """Each case's grid rows as (label, line as printed), in order. A case run twice keeps its
    last run's rows."""
    found: dict[str, list[tuple[str, str]]] = {}
    case = None
    for raw in lines:
        line = ansi.sub("", raw).replace("garden> ", "")
        if match := marker.search(line):
            case = match.group(1)
            found[case] = []
        elif case is not None and (match := row.match(line)):
            found[case].append((match.group(1), raw))
    return found


def report() -> int:
    """Reads the REPL's output and prints each case colibri disagrees on. Returns how many cases
    went uncompared."""
    rows_of = grids(sys.stdin)
    findings = []
    compared = 0
    for name, _ in cases():
        rows = rows_of.get(name, [])
        # The grid's first row: colibri against itself, then against each origin in row order.
        if not rows or rows[0][0] != "colibri":
            continue
        origins = [label for label, _ in rows[1:]]
        colours = row_colours(rows[0][1])[1:]
        if len(colours) != len(origins):
            continue
        compared += 1
        differing = [origin for origin, colour in zip(origins, colours) if colour == differs]
        failing = [origin for origin, colour in zip(origins, colours) if colour == invalid]
        if differing or failing:
            findings.append((name, len(origins), differing, failing))
    print(f"http_garden: cases={len(cases())} compared={compared} disagreements={len(findings)}")
    for name, count, differing, failing in findings:
        if differing:
            print(f"http_garden: {name}: colibri parses it differently from {len(differing)} of {count}: {' '.join(differing)}")
        if failing:
            print(f"http_garden: {name}: a parse fails the Garden's RFC check against {len(failing)} of {count}: {' '.join(failing)}")
    return len(cases()) - compared


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "names":
        for name, _ in cases():
            print(name)
        return 0
    if command == "case" and len(sys.argv) > 2:
        octets = dict(cases()).get(sys.argv[2])
        if octets is None:
            print(f"driver.py: no case named {sys.argv[2]}", file=sys.stderr)
            return 2
        case_commands(sys.argv[2], octets, sys.argv[3:])
        return 0
    if command == "report":
        # A case the REPL printed no grid for was not compared, which fails the run.
        return 1 if report() != 0 else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
