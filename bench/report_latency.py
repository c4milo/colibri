"""The report of bench/run_latency.sh (design §8 step 13f).

It reads oha's JSON for each round, protocol, server and rate, discards round 0, the warm-up, and
writes for each protocol, server and rate the median and the spread of the counted rounds: the
requests per second oha reached, and the p50, p99 and p99.9 latency. A rate is sustained when the
median p99 stays under the bound, every request was answered 200, and oha reached 95% of the rate
in every round. The summary gives each server's highest sustained rate.

    python3 bench/report_latency.py <scratch> <report.md> --p99-bound-ms <ms>
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


def report(scratch, bound_ms):
    runs = read_runs(scratch)
    machine = pathlib.Path(scratch, "machine.txt").read_text()
    protocols = sorted({key[0] for key in runs})
    lines = ["# Latency at fixed rates (design §8 step 13f)", "", "```text", machine.rstrip(), "```", ""]
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
    return "\n".join(lines) + "\n"


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
    print("report_latency.py: the report reads the runs as the tests require")


def main(argv):
    if argv[1:] == ["--test"]:
        test()
        return
    if len(argv) != 5 or argv[3] != "--p99-bound-ms":
        sys.exit(__doc__)
    pathlib.Path(argv[2]).write_text(report(argv[1], float(argv[4])))


if __name__ == "__main__":
    main(sys.argv)
