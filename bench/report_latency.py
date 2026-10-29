"""The report of bench/run_latency.sh (design §8 steps 13f and 13i).

It reads oha's JSON for each round, protocol, server and rate, discards round 0, the warm-up, and
writes for each protocol, server and rate the median and the spread of the counted rounds: the
requests per second oha reached, and the p50, p99 and p99.9 latency. A rate is sustained when the
median p99 stays under the bound, every request was answered 200, and oha reached 95% of the rate
in every round. The summary gives each server's highest sustained rate.

With --network the runs are named <protocol>@<profile>, one for each network profile of step 13i.
The report then gives no sustained rate, since a round trip of 100 ms passes any bound a clean
path sets. In its place it gives, for each profile, server and rate, the median p99 over h3
divided by the median p99 over h2-tls.

With --waits each run also has a <rate>.waits beside its JSON: the lines of `perf sched timehist`
for the server's process (design §8 step 13j). The report gives, for each protocol, server and
rate, the median over the counted rounds of: the times the server ran in a second, how long a run
took at p50, p99 and its longest, how long the server waited for its core once woken, at p99 and
its longest, and how long it slept before a run, at p50 and p99.

    python3 bench/report_latency.py <scratch> <report.md> --p99-bound-ms <ms>
    python3 bench/report_latency.py <scratch> <report.md> --network
    python3 bench/report_latency.py <scratch> <report.md> --waits
    python3 bench/report_latency.py --test
"""

import json
import pathlib
import statistics
import sys
import tempfile

# The share of a rate that oha must reach for the rate to count as sustained.
REACHED_SHARE = 0.95
# Milliseconds in a second: oha reports seconds.
MS = 1000.0
PERCENTILES = ("p50", "p99", "p99.9")


def read_runs(scratch):
    """{(protocol, server, rate): [measurement of each counted round]}."""
    runs = {}
    for path in sorted(pathlib.Path(scratch, "runs").glob("*/*/*/*.json")):
        round_, protocol, server = path.parts[-4], path.parts[-3], path.parts[-2]
        if round_ == "0":
            continue
        rate = int(path.stem)
        data = json.loads(path.read_text())
        codes = data.get("statusCodeDistribution") or {}
        answered = sum(codes.values())
        measurement = {
            "rps": data["summary"]["requestsPerSec"],
            "ok": answered > 0 and codes.get("200", 0) == answered and data["summary"]["successRate"] == 1.0,
        }
        for name in PERCENTILES:
            measurement[name] = data["latencyPercentiles"][name] * MS
        runs.setdefault((protocol, server, rate), []).append(measurement)
    return runs


def spread(values):
    return f"{statistics.median(values):.2f} ({min(values):.2f}–{max(values):.2f})"


def sustained(measurements, rate, bound_ms):
    if not all(m["ok"] for m in measurements):
        return False
    if any(m["rps"] < REACHED_SHARE * rate for m in measurements):
        return False
    return statistics.median(m["p99"] for m in measurements) <= bound_ms


def header(scratch, title):
    machine = pathlib.Path(scratch, "machine.txt").read_text()
    return [f"# {title}", "", "```text", machine.rstrip(), "```", ""]


def report(scratch, bound_ms):
    runs = read_runs(scratch)
    protocols = sorted({key[0] for key in runs})
    lines = header(scratch, "Latency at fixed rates (design §8 step 13f)")
    lines += ["## Highest sustained rate", "",
              f"The highest rate whose median p99 stays under {bound_ms} ms, with every request answered "
              f"200 and {REACHED_SHARE:.0%} of the rate reached in every round.", ""]
    lines += ["| Server | " + " | ".join(protocols) + " |", "|---|" + "---|" * len(protocols)]
    servers = sorted({key[1] for key in runs})
    for server in servers:
        cells = []
        for protocol in protocols:
            rates = sorted(rate for (p, s, rate) in runs if p == protocol and s == server)
            held = [rate for rate in rates if sustained(runs[(protocol, server, rate)], rate, bound_ms)]
            cells.append(f"{max(held)} req/s" if held else ("none" if rates else "—"))
        lines.append(f"| {server} | " + " | ".join(cells) + " |")
    return "\n".join(lines + details(runs, protocols, servers)) + "\n"


def details(runs, protocols, servers):
    """The table of each protocol: the medians and the spread of every server at every rate."""
    lines = []
    for protocol in protocols:
        lines += ["", f"## {protocol}", "",
                  "Medians, with the lowest and the highest round in parentheses. Latency in milliseconds.", "",
                  "| Server | Rate | Reached req/s | p50 | p99 | p99.9 | All 200 |", "|---|---|---|---|---|---|---|"]
        for server in servers:
            for rate in sorted(rate for (p, s, rate) in runs if p == protocol and s == server):
                measurements = runs[(protocol, server, rate)]
                cells = [spread([m["rps"] for m in measurements])]
                cells += [spread([m[name] for m in measurements]) for name in PERCENTILES]
                cells.append("yes" if all(m["ok"] for m in measurements) else "no")
                lines.append(f"| {server} | {rate} | " + " | ".join(cells) + " |")
    return lines


def median_p99(runs, key):
    return statistics.median(m["p99"] for m in runs[key])


def network_report(scratch):
    """The report of --network: h3's p99 over h2-tls's for each profile, server and rate."""
    runs = read_runs(scratch)
    labels = sorted({key[0] for key in runs})
    profiles = sorted({label.split("@")[1] for label in labels})
    servers = sorted({key[1] for key in runs})
    lines = header(scratch, "Latency on a path with delay and loss (design §8 step 13i)")
    lines += ["## h3 against h2-tls", "",
              "The median p99 over h3 divided by the median p99 over h2-tls, for one server at one "
              "rate. Below 1, h3 answers the slowest requests sooner. A dash marks a rate one of "
              "the two did not answer 200 to every request in every round.", ""]
    rates = sorted({key[2] for key in runs})
    lines += ["| Profile | Server | " + " | ".join(f"{rate} req/s" for rate in rates) + " |",
              "|---|---|" + "---|" * len(rates)]
    for profile in profiles:
        for server in servers:
            cells = []
            for rate in rates:
                h3, tcp = (f"h3@{profile}", server, rate), (f"h2-tls@{profile}", server, rate)
                held = h3 in runs and tcp in runs and all(m["ok"] for m in runs[h3] + runs[tcp])
                cells.append(f"{median_p99(runs, h3) / median_p99(runs, tcp):.2f}" if held else "—")
            lines.append(f"| {profile} | {server} | " + " | ".join(cells) + " |")
    return "\n".join(lines + details(runs, labels, servers)) + "\n"


# The columns of a `perf sched timehist` line after the task: the time the task slept before it
# ran, the time it waited for the core once woken, and the time it ran, in milliseconds.
TIMEHIST_COLUMNS = 3
# The figures of each run's record that --waits reports, by name.
WAIT_FIGURES = ("runs a second", "run p50", "run p99", "run longest", "delay p99", "delay longest",
                "sleep p50", "sleep p99")


def percentile(values, share):
    """The value that `share` of `values` do not pass: the nearest rank."""
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(share * len(ordered)))]


def read_timehist(text):
    """The figures of one record, from the lines of `perf sched timehist`, or None for no line."""
    times, sleeps, delays, runs = [], [], [], []
    for line in text.splitlines():
        words = line.split()
        # A line of an event holds the time, the core, the task and the three columns. The head's
        # lines fail the parse of a number.
        if len(words) < 2 + TIMEHIST_COLUMNS:
            continue
        try:
            at = float(words[0])
            sleep, delay, run = (float(word) for word in words[-TIMEHIST_COLUMNS:])
        except ValueError:
            continue
        times.append(at)
        sleeps.append(sleep)
        delays.append(delay)
        runs.append(run)
    if len(runs) < 2:
        return None
    span = times[-1] - times[0]
    return {
        # The span from the first run to the last holds one run fewer than the record.
        "runs a second": (len(runs) - 1) / span if span > 0 else float(len(runs)),
        "run p50": percentile(runs, 0.5), "run p99": percentile(runs, 0.99), "run longest": max(runs),
        "delay p99": percentile(delays, 0.99), "delay longest": max(delays),
        "sleep p50": percentile(sleeps, 0.5), "sleep p99": percentile(sleeps, 0.99),
    }


def read_waits(scratch):
    """{(protocol, server, rate): [figures of each counted round]}."""
    waits = {}
    for path in sorted(pathlib.Path(scratch, "runs").glob("*/*/*/*.waits")):
        round_, protocol, server = path.parts[-4], path.parts[-3], path.parts[-2]
        if round_ == "0":
            continue
        figures = read_timehist(path.read_text())
        if figures is not None:
            waits.setdefault((protocol, server, int(path.stem)), []).append(figures)
    return waits


def waits_report(scratch):
    """The report of --waits: where each server spent the time between its requests."""
    runs = read_runs(scratch)
    waits = read_waits(scratch)
    protocols = sorted({key[0] for key in runs})
    servers = sorted({key[1] for key in runs})
    lines = header(scratch, "Where the server waits under load (design §8 step 13j)")
    lines += ["## Runs of the server", "",
              "Medians over the counted rounds of `perf sched timehist` on the server's core. A run is "
              "one stretch on the core between two sleeps. Times in milliseconds: \"delay\" is the wait "
              "for the core once woken, and \"sleep\" is the time before a run. A dash marks a load "
              "with no record.", ""]
    lines += ["| Protocol | Server | Rate | " + " | ".join(WAIT_FIGURES) + " |",
              "|---|---|---|" + "---|" * len(WAIT_FIGURES)]
    for protocol in protocols:
        for server in servers:
            for rate in sorted(rate for (p, s, rate) in runs if p == protocol and s == server):
                rounds = waits.get((protocol, server, rate))
                cells = [f"{statistics.median(r[name] for r in rounds):.3f}" if rounds else "—"
                         for name in WAIT_FIGURES]
                lines.append(f"| {protocol} | {server} | {rate} | " + " | ".join(cells) + " |")
    return "\n".join(lines + details(runs, protocols, servers)) + "\n"


def write_run(scratch, round_, protocol, server, rate, rps, p99, codes):
    path = pathlib.Path(scratch, "runs", str(round_), protocol, server, f"{rate}.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    percentiles = {"p50": p99 / 4, "p99": p99, "p99.9": p99 * 2}
    data = {"summary": {"requestsPerSec": rps, "successRate": 1.0}, "statusCodeDistribution": codes,
            "latencyPercentiles": {name: value / MS for name, value in percentiles.items()}}
    path.write_text(json.dumps(data))


def test():
    with tempfile.TemporaryDirectory() as scratch:
        pathlib.Path(scratch, "machine.txt").write_text("rounds=2\n")
        for round_ in (0, 1, 2):
            # The warm-up's numbers are wrong on purpose: the report must discard them.
            warm = round_ == 0
            write_run(scratch, round_, "h11", "a", 1000, 1000, 99 if warm else 1, {"200": 10})
            write_run(scratch, round_, "h11", "a", 2000, 2000, 2 + round_, {"200": 10})
            write_run(scratch, round_, "h11", "b", 1000, 1000, 50, {"200": 10})
            write_run(scratch, round_, "h11", "b", 2000, 1500, 1, {"200": 10})
            write_run(scratch, round_, "h2", "a", 1000, 1000, 1, {"200": 9, "503": 1})
        text = report(scratch, 10)
        # a holds 2000 on h11; on h2 one answer was a 503, so a holds none there.
        assert "| a | 2000 req/s | none |" in text, text
        # b's p99 passes the bound at 1000, and oha reached 75% of 2000 alone.
        assert "| b | none | — |" in text, text
        assert "| a | 1000 | 1000.00 (1000.00–1000.00) | 0.25 (0.25–0.25) | 1.00 (1.00–1.00) |" in text, text
        assert "| a | 2000 | 2000.00 (2000.00–2000.00) | 0.88 (0.75–1.00) | 3.50 (3.00–4.00) |" in text, text
    with tempfile.TemporaryDirectory() as scratch:
        pathlib.Path(scratch, "machine.txt").write_text("rounds=2\n")
        test_network(scratch)
    with tempfile.TemporaryDirectory() as scratch:
        pathlib.Path(scratch, "machine.txt").write_text("rounds=2\n")
        test_waits(scratch)
    print("report_latency.py: the report reads the runs as the tests require")


def test_network(scratch):
    for round_ in (0, 1, 2):
        warm = round_ == 0
        write_run(scratch, round_, "h3@lossy", "a", 1000, 1000, 99 if warm else 30, {"200": 10})
        write_run(scratch, round_, "h2-tls@lossy", "a", 1000, 1000, 60, {"200": 10})
        write_run(scratch, round_, "h3@lossy", "a", 2000, 2000, 30, {"200": 9, "503": 1})
        write_run(scratch, round_, "h2-tls@lossy", "a", 2000, 2000, 60, {"200": 10})
    text = network_report(scratch)
    # At 1000 req/s, h3's p99 is half of h2-tls's; at 2000 one h3 answer was a 503.
    assert "| lossy | a | 0.50 | — |" in text, text
    assert "## h3@lossy" in text and "Highest sustained rate" not in text, text


# The head of `perf sched timehist`, which the parse skips.
TIMEHIST_HEAD = """           time    cpu  task name                       wait time  sch delay   run time
                        [tid/pid]                          (msec)     (msec)     (msec)
--------------- ------  ------------------------------  ---------  ---------  ---------
"""


def timehist_lines(sleeps, delays, runs, start=100.0, step=0.01):
    """Lines of `perf sched timehist` for one task, `step` seconds apart."""
    rows = [f"{start + index * step:15.6f} [0001]  http-server[42]  {sleep:9.3f}  {delay:9.3f}  {run:9.3f}"
            for index, (sleep, delay, run) in enumerate(zip(sleeps, delays, runs))]
    return TIMEHIST_HEAD + "\n".join(rows) + "\n"


def test_waits(scratch):
    # One counted round, so a warm-up the report does not discard changes each median.
    for round_ in (0, 1):
        warm = round_ == 0
        write_run(scratch, round_, "h2-tls", "a", 1000, 1000, 5, {"200": 10})
        write_run(scratch, round_, "h2-tls", "b", 1000, 1000, 4, {"200": 10})
        # 101 runs 0.01 s apart: 100 runs a second. Run i takes i/100 ms, so p50 is 0.50 and p99
        # 0.99, and the warm-up's runs are ten times longer, which the report must discard.
        scale = 10 if warm else 1
        runs = [scale * index / 100 for index in range(101)]
        delays = [0.0] * 100 + [0.5 * round_]
        path = pathlib.Path(scratch, "runs", str(round_), "h2-tls", "a", "1000.waits")
        path.write_text(timehist_lines([0.2] * 101, delays, runs))
    text = waits_report(scratch)
    assert "| h2-tls | a | 1000 | 100.000 | 0.500 | 0.990 | 1.000 | 0.000 | 0.500 | 0.200 | 0.200 |" in text, text
    # b has no record, and its latency still has its table.
    assert "| h2-tls | b | 1000 | — |" in text and "## h2-tls" in text, text
    assert read_timehist(TIMEHIST_HEAD) is None


def main(argv):
    if argv[1:] == ["--test"]:
        test()
        return
    if len(argv) == 4 and argv[3] == "--network":
        pathlib.Path(argv[2]).write_text(network_report(argv[1]))
        return
    if len(argv) == 4 and argv[3] == "--waits":
        pathlib.Path(argv[2]).write_text(waits_report(argv[1]))
        return
    if len(argv) != 5 or argv[3] != "--p99-bound-ms":
        sys.exit(__doc__)
    pathlib.Path(argv[2]).write_text(report(argv[1], float(argv[4])))


if __name__ == "__main__":
    main(sys.argv)
