"""The report of bench/run_bulk.sh (design §8 step 13k).

It reads oha's JSON for each round, protocol and profile, server and count of connections, and
discards round 0, the warm-up. <connections>.json holds the downloads of the file, and
<connections>.probe.json the small GETs sent beside them. For each profile, protocol, server and
count of connections the report gives the median over the counted rounds of:
- the p50 and p90 time of one download. 30 s holds about 35 downloads, too few for a p99.
- the goodput: the octets of the downloads answered 200, over the seconds of the load.
- the p50 and p99 latency of the small GETs, which wait in the bottleneck's queue.
- whether every download and every GET was answered 200. A download that the end of the load
  cut is no answer, and oha counts it as an error, so it does not count against this.

    python3 bench/report_bulk.py <scratch> <report.md> --file-len <octets> --seconds <seconds>
    python3 bench/report_bulk.py --test
"""

import json
import pathlib
import statistics
import sys
import tempfile

# Milliseconds in a second: oha reports seconds.
MS = 1000.0
# Bits in an octet, and bits in a megabit.
BITS = 8
MEGABIT = 1_000_000


def answered(data):
    """The answers of one load that were 200, and whether every answer was."""
    codes = data.get("statusCodeDistribution") or {}
    ok = codes.get("200", 0)
    return ok, ok > 0 and ok == sum(codes.values())


def read_runs(scratch, file_len, seconds):
    """{(profile, protocol, server, connections): [measurement of each counted round]}."""
    runs = {}
    for path in sorted(pathlib.Path(scratch, "runs").glob("*/*/*/*.json")):
        round_, label, server = path.parts[-4], path.parts[-3], path.parts[-2]
        if round_ == "0" or path.name.endswith(".probe.json"):
            continue
        protocol, profile = label.split("@")
        connections = int(path.stem)
        downloads = json.loads(path.read_text())
        probe = json.loads(path.with_name(f"{connections}.probe.json").read_text())
        count, downloads_ok = answered(downloads)
        _, probe_ok = answered(probe)
        runs.setdefault((profile, protocol, server, connections), []).append({
            "p50": downloads["latencyPercentiles"]["p50"] * MS,
            "p90": downloads["latencyPercentiles"]["p90"] * MS,
            "goodput": count * file_len * BITS / seconds / MEGABIT,
            "probe p50": probe["latencyPercentiles"]["p50"] * MS,
            "probe p99": probe["latencyPercentiles"]["p99"] * MS,
            "ok": downloads_ok and probe_ok,
        })
    return runs


FIGURES = (("p50", "download p50 (ms)", "{:.0f}"), ("p90", "download p90 (ms)", "{:.0f}"),
           ("goodput", "goodput (Mbit/s)", "{:.2f}"), ("probe p50", "GET p50 (ms)", "{:.1f}"),
           ("probe p99", "GET p99 (ms)", "{:.1f}"))


def row(key, measurements):
    profile, protocol, server, connections = key
    cells = [fmt.format(statistics.median(m[name] for m in measurements)) for name, _, fmt in FIGURES]
    cells.append("yes" if all(m["ok"] for m in measurements) else "no")
    return f"| {protocol} | {server} | {connections} | " + " | ".join(cells) + " |"


def report(scratch, file_len, seconds):
    runs = read_runs(scratch, file_len, seconds)
    machine = pathlib.Path(scratch, "machine.txt").read_text()
    lines = ["# Bulk downloads at a bottleneck", "", "```text", machine.rstrip(), "```", "",
             "The median over the counted rounds. A GET is a small file, sent each 100 ms on a "
             "connection of its own beside the downloads.", ""]
    for profile in sorted({key[0] for key in runs}):
        lines += [f"## {profile}", "",
                  "| Protocol | Server | Connections | " + " | ".join(title for _, title, _ in FIGURES) + " | All 200 |",
                  "|---|---|---|" + "---|" * (len(FIGURES) + 1)]
        lines += [row(key, runs[key]) for key in sorted(runs) if key[0] == profile]
        lines.append("")
    return "\n".join(lines)


def write_run(scratch, round_, label, server, connections, p50, count, codes):
    """One load: downloads whose p50 is `p50` seconds, `count` of them 200 and `codes` beside,
    and a probe whose p50 is a tenth of that."""
    directory = pathlib.Path(scratch, "runs", str(round_), label, server)
    directory.mkdir(parents=True, exist_ok=True)
    downloads = {"statusCodeDistribution": {"200": count, **codes},
                 "latencyPercentiles": {"p50": p50, "p90": p50 * 2}}
    probe = {"statusCodeDistribution": {"200": 300}, "latencyPercentiles": {"p50": p50 / 10, "p99": p50 / 5}}
    pathlib.Path(directory, f"{connections}.json").write_text(json.dumps(downloads))
    pathlib.Path(directory, f"{connections}.probe.json").write_text(json.dumps(probe))


def test():
    with tempfile.TemporaryDirectory() as scratch:
        pathlib.Path(scratch, "machine.txt").write_text("rounds=2\n")
        for round_ in (0, 1, 2):
            # The warm-up's numbers are wrong on purpose: the report must discard them.
            warm = round_ == 0
            write_run(scratch, round_, "h3@bottleneck", "a", 1, 9.0 if warm else 1.0, 30, {})
            write_run(scratch, round_, "h3@bottleneck", "a", 4, 4.0, 10 * round_, {})
            write_run(scratch, round_, "h2-tls@bottleneck-lossy", "b", 1, 2.0, 15, {"503": 1})
        # 30 downloads of 1,000,000 octets in 30 s: 8 Mbit/s.
        text = report(scratch, 1_000_000, 30)
        assert "| h3 | a | 1 | 1000 | 2000 | 8.00 | 100.0 | 200.0 | yes |" in text, text
        # 10 and then 20 downloads, a median of 15.
        assert "| h3 | a | 4 | 4000 | 8000 | 4.00 | 400.0 | 800.0 | yes |" in text, text
        # One answer was a 503, so not every download was 200.
        assert "| h2-tls | b | 1 | 2000 | 4000 | 4.00 | 200.0 | 400.0 | no |" in text, text
        assert "## bottleneck\n" in text and "## bottleneck-lossy\n" in text, text
    print("report_bulk.py: the report reads the runs as the tests require")


def main(argv):
    if argv[1:] == ["--test"]:
        test()
        return
    if len(argv) != 7 or argv[3] != "--file-len" or argv[5] != "--seconds":
        sys.exit(__doc__)
    pathlib.Path(argv[2]).write_text(report(argv[1], int(argv[4]), float(argv[6])))


if __name__ == "__main__":
    main(sys.argv)
