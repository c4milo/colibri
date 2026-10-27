"""The report of bench/run.sh --profile (design §8 step 13h).

It reads the stacks that `perf script -F comm,ip,sym,dso` wrote for each input, as
bench/run_profile.sh lists them in profiles.csv. For each input it writes two tables to the report:
the functions that took the most samples themselves, and the functions that were on the most
stacks. It also writes the folded stacks, one line for each stack with its count, which a flame
graph reads, to `<report>-profile/<input>.folded` beside the report.

    python3 bench/report_profile.py <scratch> <report.md>
    python3 bench/report_profile.py --test
"""

import collections
import pathlib
import sys
import tempfile

# The rows of each table.
ROWS = 25


def frame_name(line):
    """The function of one frame line: `<ip> <symbol> (<dso>)`."""
    text = line.strip()
    dso = ""
    if text.endswith(")") and " (" in text:
        text, dso = text.rsplit(" (", 1)
        dso = dso[:-1]
    parts = text.split(None, 1)
    symbol = parts[1] if len(parts) > 1 else "[unknown]"
    if symbol == "[unknown]":
        return "[unknown] " + pathlib.PurePath(dso).name if dso else symbol
    return symbol + " [k]" if dso.startswith("[kernel") else symbol


def read_stacks(text):
    """[stack of each sample, the outermost frame first]."""
    stacks = []
    for block in text.split("\n\n"):
        frames = [frame_name(line) for line in block.split("\n") if line[:1].isspace() and line.strip()]
        if frames:
            stacks.append(list(reversed(frames)))
    return stacks


def table(title, counts, other, total, other_title):
    lines = [f"### {title}", "", f"| {title.split()[-1].capitalize()} | {other_title} | Function |", "|---|---|---|"]
    for name, count in counts.most_common(ROWS):
        lines.append(f"| {100 * count / total:.1f}% | {100 * other[name] / total:.1f}% | `{name}` |")
    return lines + [""]


def input_section(name, stacks):
    total = len(stacks)
    if total == 0:
        return [f"## {name}", "", "perf recorded no sample.", ""]
    own = collections.Counter(stack[-1] for stack in stacks)
    # A function counts once on each stack, however many of its frames the stack holds.
    on_stack = collections.Counter(name for stack in stacks for name in set(stack))
    lines = [f"## {name}", "", f"{total} samples.", ""]
    lines += table("By self", own, on_stack, total, "Inclusive")
    lines += table("By inclusive", on_stack, own, total, "Self")
    return lines


def folded(stacks):
    counts = collections.Counter(";".join(stack) for stack in stacks)
    return "".join(f"{stack} {count}\n" for stack, count in sorted(counts.items()))


def report(scratch, report_path):
    scratch = pathlib.Path(scratch)
    out_dir = pathlib.Path(str(report_path).removesuffix(".md") + "-profile")
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = ["# Profile of colibri's server (design §8 step 13h)", "",
             "A profile shows where the time goes. No document publishes its numbers.", "",
             "```text", (scratch / "machine.txt").read_text().strip(), "```", ""]
    for row in (scratch / "profiles.csv").read_text().splitlines():
        name, path = row.split(",", 1)
        stacks = read_stacks(pathlib.Path(path).read_text(errors="replace"))
        (out_dir / f"{name}.folded").write_text(folded(stacks))
        lines += input_section(name, stacks)
    return "\n".join(lines)


SAMPLE = """http-server
\t    aaaa0001 h2.Connection.receive (/s/bin/http-server)
\t    aaaa0002 server.Endpoint.run (/s/bin/http-server)
\t    aaaa0003 main (/s/bin/http-server)

http-server
\t    ffff0001 copy_to_user ([kernel.kallsyms])
\t    aaaa0002 server.Endpoint.run (/s/bin/http-server)
\t    aaaa0003 main (/s/bin/http-server)

http-server
\t    aaaa0001 h2.Connection.receive (/s/bin/http-server)
\t    aaaa0002 server.Endpoint.run (/s/bin/http-server)
\t    aaaa0003 main (/s/bin/http-server)

http-server
\t    bbbb0001 [unknown] (/s/bin/http-server)

http-server
\t    aaaa0004 h2.Connection.receive (inlined)
\t    aaaa0001 h2.Connection.receive (/s/bin/http-server)
\t    aaaa0002 server.Endpoint.run (/s/bin/http-server)
\t    aaaa0003 main (/s/bin/http-server)
"""


def test():
    with tempfile.TemporaryDirectory() as scratch:
        root = pathlib.Path(scratch)
        (root / "machine.txt").write_text("rounds=1\n")
        (root / "h2-many.stacks").write_text(SAMPLE)
        (root / "profiles.csv").write_text(f"h2-many,{root / 'h2-many.stacks'}\n")
        text = report(scratch, root / "report.md")
        assert "5 samples." in text, text
        # receive holds three samples itself, and counts once on the stack that holds it twice.
        # run is on four stacks and holds none itself.
        assert "| 60.0% | 60.0% | `h2.Connection.receive` |" in text, text
        assert "| 80.0% | 0.0% | `server.Endpoint.run` |" in text, text
        assert "| 20.0% | 20.0% | `copy_to_user [k]` |" in text, text
        assert "| 20.0% | 20.0% | `[unknown] http-server` |" in text, text
        stacks = (root / "report-profile" / "h2-many.folded").read_text()
        assert "main;server.Endpoint.run;h2.Connection.receive 2\n" in stacks, stacks
        assert "main;server.Endpoint.run;copy_to_user [k] 1\n" in stacks, stacks
        assert "main;server.Endpoint.run;h2.Connection.receive;h2.Connection.receive 1\n" in stacks, stacks
    print("report_profile.py: the report reads the stacks as the tests require")


def main(argv):
    if argv[1:] == ["--test"]:
        test()
        return
    if len(argv) != 3:
        sys.exit(__doc__)
    pathlib.Path(argv[2]).write_text(report(argv[1], argv[2]))


if __name__ == "__main__":
    main(sys.argv)
