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

The protocol `h3-shared` holds two servers loaded at once through one bottleneck (design §8
step 29c). For it the report also gives each server's share of the two goodputs, the median of
each counted round's share.

`resume/<round>/<profile>/<server>/<download>.json` holds one download on a connection of its
own (design §8 step 35e), and `server.txt` beside it the last counts a server with
`careful-resume` logged. Download 0 saved the set the others take, and is not counted. For each
profile and controller the report gives the median time of a download from the server as it is
and from `<server>-resume`, their ratio, and how many of the counted connections took a set and
how many retreated (RFC 9959 §3.5).

    python3 bench/report_bulk.py <scratch> <report.md> --file-len <octets> --seconds <seconds>
    python3 bench/report_bulk.py --test
"""

import json
import pathlib
import re
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


# The protocol of the runs where two servers share the bottleneck.
SHARED = "h3-shared"


def shares(runs, profile, connections):
    """{server: median share of the goodput} of the two servers that shared the bottleneck."""
    keys = [key for key in sorted(runs) if key[:2] == (profile, SHARED) and key[3] == connections]
    totals = [sum(pair) for pair in zip(*([m["goodput"] for m in runs[key]] for key in keys))]
    return {key[2]: statistics.median(m["goodput"] / total if total else 0.0
                                      for m, total in zip(runs[key], totals)) for key in keys}


def shared_section(runs):
    """The table of each server's share, or no lines when no run shared the bottleneck."""
    profiles = sorted({key[0] for key in runs if key[1] == SHARED})
    if not profiles:
        return []
    lines = ["## The bottleneck shared", "",
             "Two servers loaded at once through one bottleneck, each with its own downloads. The "
             "share is one server's goodput over the two, the median over the counted rounds.", "",
             "| Profile | Connections each | Server | Share |", "|---|---|---|---|"]
    for profile in profiles:
        for connections in sorted({key[3] for key in runs if key[:2] == (profile, SHARED)}):
            for server, share in shares(runs, profile, connections).items():
                lines.append(f"| {profile} | {connections} | {server} | {share:.2f} |")
    return lines + [""]


# What a server with `careful-resume` is named after, and the counts its log gives.
RESUME = "-resume"
COUNTS = re.compile(r"resumed=(\d+) saved=\d+ retreated=(\d+)")


def read_resume(scratch):
    """{(profile, server): {"ms": [each counted download], "ok", "resumed", "retreated"}}."""
    runs = {}
    for path in sorted(pathlib.Path(scratch, "resume").glob("*/*/*/server.txt")):
        round_, profile, server = path.parts[-4], path.parts[-3], path.parts[-2]
        if round_ == "0":
            continue
        run = runs.setdefault((profile, server), {"ms": [], "ok": True, "resumed": 0, "retreated": 0})
        for download in sorted(path.parent.glob("*.json")):
            if download.stem == "0":
                continue
            data = json.loads(download.read_text())
            # The one request's time, from its start on the open connection to its last octet.
            # `total` also holds the idle timeout oha waits out before it ends. oha gives no
            # time for a download it did not complete, which the report does not count.
            slowest = data["summary"]["slowest"]
            run["ok"] = run["ok"] and answered(data)[1] and slowest is not None
            if slowest is not None:
                run["ms"].append(slowest * MS)
        counts = COUNTS.search(path.read_text())
        if counts:
            run["resumed"] += int(counts.group(1))
            run["retreated"] += int(counts.group(2))
    return runs


def resume_section(scratch):
    """The table of the downloads on connections of their own, or no lines when none ran."""
    runs = read_resume(scratch)
    if not runs:
        return []
    lines = ["## A download on a connection of its own", "",
             "Each download ran alone, on a connection of its own. `New` is a server that starts "
             "each connection with no saved set. `Resumed` is that server with `careful-resume`, "
             "which gives each connection what the one before it observed (RFC 9959). A time is "
             "the median over the downloads of the counted rounds.", "",
             "| Profile | Server | Downloads | New (ms) | Resumed (ms) | Resumed / new | Took a set | Retreated | All 200 |",
             "|---|---|---|---|---|---|---|---|---|"]
    for profile, server in sorted(runs):
        resumed = runs.get((profile, server + RESUME))
        if server.endswith(RESUME) or resumed is None:
            continue
        new = runs[(profile, server)]
        if not new["ms"] or not resumed["ms"]:
            lines.append(f"| {profile} | {server} | {len(resumed['ms'])} | - | - | - | "
                         f"{resumed['resumed']} | {resumed['retreated']} | no |")
            continue
        new_ms, resumed_ms = statistics.median(new["ms"]), statistics.median(resumed["ms"])
        ok = "yes" if new["ok"] and resumed["ok"] else "no"
        lines.append(f"| {profile} | {server} | {len(resumed['ms'])} | {new_ms:.0f} | {resumed_ms:.0f} | "
                     f"{resumed_ms / new_ms:.2f} | {resumed['resumed']} | {resumed['retreated']} | {ok} |")
    return lines + [""]


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
    return "\n".join(lines + shared_section(runs) + resume_section(scratch))


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


def write_resume(scratch, round_, server, seconds, counts):
    """The downloads of one server of `h3-resume`: download 0 and one of each of `seconds`, where
    None is a download that oha did not complete."""
    directory = pathlib.Path(scratch, "resume", str(round_), "bottleneck", server)
    directory.mkdir(parents=True, exist_ok=True)
    for download, slowest in enumerate((9.0, *seconds)):
        data = {"summary": {"slowest": slowest, "total": 12.0},
                "statusCodeDistribution": {} if slowest is None else {"200": 1}}
        pathlib.Path(directory, f"{download}.json").write_text(json.dumps(data))
    pathlib.Path(directory, "server.txt").write_text(counts)


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
        assert "## The bottleneck shared" not in text, text
        # Two servers at once: 30 and 10 downloads, then 20 and 20, shares of 0.75 and 0.5.
        for round_, counts in ((0, (1, 1)), (1, (30, 10)), (2, (20, 20))):
            write_run(scratch, round_, "h3-shared@bottleneck", "cubic", 1, 1.0, counts[0], {})
            write_run(scratch, round_, "h3-shared@bottleneck", "bbr", 1, 1.0, counts[1], {})
        text = report(scratch, 1_000_000, 30)
        assert "| bottleneck | 1 | cubic | 0.62 |" in text, text
        assert "| bottleneck | 1 | bbr | 0.38 |" in text, text
        assert "## A download on a connection of its own" not in text, text
        # Round 0 and download 0 are not counted. The medians are 1.0 s and 0.8 s, and of the 4
        # connections that the server with `careful-resume` counted, 3 took a set and 1 retreated.
        for round_ in (0, 1, 2):
            warm = round_ == 0
            write_resume(scratch, round_, "a", (9.0, 9.0) if warm else (0.9, 1.1), "")
            line = "quic-udp: careful-resume: ended=3 resumed=%d saved=3 retreated=%d\n" % ((9, 9) if warm else (round_, round_ - 1))
            write_resume(scratch, round_, "a-resume", (9.0, 9.0) if warm else (0.7, 0.9), line)
        text = report(scratch, 1_000_000, 30)
        assert "| bottleneck | a | 4 | 1000 | 800 | 0.80 | 3 | 1 | yes |" in text, text
        # A download that oha did not complete has no time: it is not counted, and not all were 200.
        write_resume(scratch, 1, "b", (1.0, None), "")
        write_resume(scratch, 1, "b-resume", (0.5, 0.5), "")
        write_resume(scratch, 1, "c", (None,), "")
        write_resume(scratch, 1, "c-resume", (0.5,), "")
        text = report(scratch, 1_000_000, 30)
        assert "| bottleneck | b | 2 | 1000 | 500 | 0.50 | 0 | 0 | no |" in text, text
        assert "| bottleneck | c | 1 | - | - | - | 0 | 0 | no |" in text, text
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
