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
its longest, and how long it slept before a run, at p50 and p99. A <rate>.pcap holds the heads of
the packets of both directions for part of the load, and a <rate>.port the server's port. From
them the report gives the server's TCP segments with data for each response, at the rate oha
reached, and the octets of data in each. It also gives the turns of each connection: the time the
server took to answer a segment of requests, and the time the client took to send the next one.
A <rate>.counts holds what `perf stat` counted of the server for a part of the load, with the
time it counted for. From it the report gives the server's instructions, cycles and system calls
for each request, at the rate oha reached, and the share of its core the server used.

    python3 bench/report_latency.py <scratch> <report.md> --p99-bound-ms <ms>
    python3 bench/report_latency.py <scratch> <report.md> --network
    python3 bench/report_latency.py <scratch> <report.md> --waits
    python3 bench/report_latency.py --test
"""

import json
import pathlib
import statistics
import struct
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


# The pcap file format: its magic number, the length of its file header and of each record's
# header, and the link types a capture on the loopback device can carry: Ethernet, Linux cooked
# capture and its second version.
PCAP_MAGIC = 0xA1B2C3D4
PCAP_FILE_HEADER_LEN = 24
PCAP_RECORD_HEADER_LEN = 16
LINK_HEADER_LEN = {1: 14, 113: 16, 276: 20}
IPV4 = 4
# Microseconds in a second, which a pcap record's time counts below its seconds.
US = 1_000_000


def read_packets(data):
    """[(time, source port, destination port, octets of data)] of the IPv4 TCP packets of a pcap,
    or None for a file that is not one. Each length comes from the IP and TCP headers, so a
    capture of the heads alone serves."""
    if len(data) < PCAP_FILE_HEADER_LEN or struct.unpack("<I", data[:4])[0] != PCAP_MAGIC:
        return None
    skip = LINK_HEADER_LEN.get(struct.unpack("<I", data[20:24])[0])
    if skip is None:
        return None
    packets, offset = [], PCAP_FILE_HEADER_LEN
    while offset + PCAP_RECORD_HEADER_LEN <= len(data):
        seconds, micros, captured, _ = struct.unpack("<IIII", data[offset:offset + PCAP_RECORD_HEADER_LEN])
        packet = data[offset + PCAP_RECORD_HEADER_LEN:offset + PCAP_RECORD_HEADER_LEN + captured]
        offset += PCAP_RECORD_HEADER_LEN + captured
        ip = packet[skip:]
        if len(ip) < 20 or ip[0] >> 4 != IPV4:
            continue
        ip_header_len = (ip[0] & 0x0F) * 4
        source, destination = struct.unpack(">HH", ip[ip_header_len:ip_header_len + 4])
        tcp_header_len = (ip[ip_header_len + 12] >> 4) * 4
        payload = struct.unpack(">H", ip[2:4])[0] - ip_header_len - tcp_header_len
        packets.append((seconds + micros / US, source, destination, payload))
    return packets


def read_turns(packets, port):
    """The turns of each connection to the server on `port`, or None for no turn. An answer runs
    from the first segment of requests after an answer to the first segment that answers it. A
    next request runs from that segment to the client's next segment of requests. A segment with
    no data, such as an acknowledgment, starts and ends nothing."""
    request_at, answer_at, answers, next_requests = {}, {}, [], []
    for at, source, destination, payload in packets:
        if payload <= 0:
            continue
        if source == port:
            if request_at.get(destination) is not None:
                answers.append((at - request_at[destination]) * MS)
                request_at[destination] = None
            if answer_at.get(destination) is None:
                answer_at[destination] = at
        elif destination == port:
            if answer_at.get(source) is not None:
                next_requests.append((at - answer_at[source]) * MS)
                answer_at[source] = None
            if request_at.get(source) is None:
                request_at[source] = at
    if not answers or not next_requests:
        return None
    return {"answer p50": percentile(answers, 0.5), "answer mean": statistics.fmean(answers),
            "next request p50": percentile(next_requests, 0.5),
            "next request mean": statistics.fmean(next_requests)}


def read_capture(data, port=None):
    """The server's segments with data a second and their octets of data each, from a pcap, with
    the turns of each connection when `port` names the server's port. None for fewer than two of
    the server's segments. With no port, every segment with data is the server's."""
    packets = read_packets(data)
    if packets is None:
        return None
    sent = [(at, payload) for at, source, _, payload in packets
            if payload > 0 and (port is None or source == port)]
    if len(sent) < 2 or sent[-1][0] <= sent[0][0]:
        return None
    figures = {"segments a second": (len(sent) - 1) / (sent[-1][0] - sent[0][0]),
               "octets a segment": sum(payload for _, payload in sent) / len(sent)}
    turns = read_turns(packets, port) if port is not None else None
    if turns is not None:
        figures.update(turns)
    return figures


def read_captures(scratch):
    """{(protocol, server, rate): [figures of each counted round's capture]}."""
    captures = {}
    for path in sorted(pathlib.Path(scratch, "runs").glob("*/*/*/*.pcap")):
        round_, protocol, server = path.parts[-4], path.parts[-3], path.parts[-2]
        if round_ == "0":
            continue
        port_path = path.with_suffix(".port")
        port = int(port_path.read_text()) if port_path.exists() else None
        figures = read_capture(path.read_bytes(), port)
        if figures is not None:
            captures.setdefault((protocol, server, int(path.stem)), []).append(figures)
    return captures


def capture_cells(captures, runs, key):
    """The segments a response and the octets a segment of `key`, as medians, or dashes."""
    rounds = captures.get(key)
    if not rounds:
        return ["—", "—"]
    reached = statistics.median(m["rps"] for m in runs[key])
    per_response = statistics.median(r["segments a second"] for r in rounds) / reached
    return [f"{per_response:.3f}", f"{statistics.median(r['octets a segment'] for r in rounds):.1f}"]


# The events of a run's counts, by the names perf stat writes. `duration_time` is the time perf
# counted for, in nanoseconds.
COUNT_EVENTS = ("instructions:u", "instructions:k", "cycles:u", "cycles:k", "task-clock",
                "raw_syscalls:sys_enter", "duration_time")
# The nanoseconds in one unit of task-clock, by the unit perf stat writes beside it, as
# bench/report.py reads it.
TASK_CLOCK_NANOSECONDS = {"": 1.0, "ns": 1.0, "nsec": 1.0, "usec": 1e3, "msec": 1e6}
NANOSECONDS_PER_SECOND = 1e9
COUNT_COLUMNS = ("instructions a request", "user instructions a request", "cycles a request",
                 "user cycles a request", "system calls a request", "share of the core")


def read_count(text):
    """What one `perf stat -x,` file holds, each count for a second of the time perf counted, and
    the share of that time the server ran. None when perf did not count an event."""
    counts = {}
    for line in text.splitlines():
        fields = line.strip().split(",")
        if len(fields) < 3 or line.startswith("#") or fields[2] not in COUNT_EVENTS:
            continue
        try:
            counts[fields[2]] = float(fields[0])
        except ValueError:
            # perf writes "<not counted>" or "<not supported>" in place of a number.
            return None
        if fields[2] == "task-clock":
            if fields[1] not in TASK_CLOCK_NANOSECONDS:
                return None
            counts[fields[2]] *= TASK_CLOCK_NANOSECONDS[fields[1]]
    if set(counts) != set(COUNT_EVENTS) or counts["duration_time"] <= 0:
        return None
    seconds = counts["duration_time"] / NANOSECONDS_PER_SECOND
    return {
        "instructions a second": (counts["instructions:u"] + counts["instructions:k"]) / seconds,
        "user instructions a second": counts["instructions:u"] / seconds,
        "cycles a second": (counts["cycles:u"] + counts["cycles:k"]) / seconds,
        "user cycles a second": counts["cycles:u"] / seconds,
        "system calls a second": counts["raw_syscalls:sys_enter"] / seconds,
        "share of the core": counts["task-clock"] / counts["duration_time"],
    }


def read_counts(scratch):
    """{(protocol, server, rate): [figures of each counted round's counts]}."""
    counts = {}
    for path in sorted(pathlib.Path(scratch, "runs").glob("*/*/*/*.counts")):
        round_, protocol, server = path.parts[-4], path.parts[-3], path.parts[-2]
        if round_ == "0":
            continue
        figures = read_count(path.read_text())
        if figures is not None:
            counts.setdefault((protocol, server, int(path.stem)), []).append(figures)
    return counts


def count_cells(counts, runs, key):
    """The counts of `key` for each request, as medians at the rate oha reached, or dashes."""
    rounds = counts.get(key)
    if not rounds:
        return ["—"] * len(COUNT_COLUMNS)
    reached = statistics.median(m["rps"] for m in runs[key])
    cells = []
    for column in COUNT_COLUMNS[:-1]:
        a_second = statistics.median(r[column.replace("a request", "a second")] for r in rounds)
        cells.append(f"{a_second / reached:,.1f}" if "calls" not in column else f"{a_second / reached:.3f}")
    return cells + [f"{statistics.median(r['share of the core'] for r in rounds):.3f}"]


def counts_table(scratch, runs, protocols, servers):
    """The lines of the table of counts: one row for each protocol, server and rate."""
    counts = read_counts(scratch)
    lines = ["", "## Counts of the server", "",
             "Medians over the counted rounds of `perf stat` on the server's process, after the "
             "record, each divided by the rate oha reached. The share of the core is the time the "
             "server ran over the time perf counted for. A dash marks a load with no counts.", "",
             "| Protocol | Server | Rate | " + " | ".join(COUNT_COLUMNS) + " |",
             "|---|---|---|" + "---|" * len(COUNT_COLUMNS)]
    for protocol in protocols:
        for server in servers:
            for rate in sorted(rate for (p, s, rate) in runs if p == protocol and s == server):
                cells = count_cells(counts, runs, (protocol, server, rate))
                lines.append(f"| {protocol} | {server} | {rate} | " + " | ".join(cells) + " |")
    return lines


TURN_COLUMNS = ("answer p50", "answer mean", "next request p50", "next request mean")


def turns_table(captures, runs, protocols, servers):
    """The lines of the table of turns: one row for each protocol, server and rate."""
    lines = ["", "## Turns of each connection", "",
             "Medians over the counted rounds, from the capture of both directions. On each "
             "connection, \"answer\" is the time from the first segment of requests after an answer "
             "to the first segment that answers it, and \"next request\" is the time from that "
             "segment to the client's next segment of requests. Times in milliseconds. A dash marks "
             "a load with no capture of both directions.", "",
             "| Protocol | Server | Rate | " + " | ".join(TURN_COLUMNS) + " |",
             "|---|---|---|" + "---|" * len(TURN_COLUMNS)]
    for protocol in protocols:
        for server in servers:
            for rate in sorted(rate for (p, s, rate) in runs if p == protocol and s == server):
                rounds = [r for r in captures.get((protocol, server, rate), []) if TURN_COLUMNS[0] in r]
                cells = [f"{statistics.median(r[name] for r in rounds):.3f}" if rounds else "—"
                         for name in TURN_COLUMNS]
                lines.append(f"| {protocol} | {server} | {rate} | " + " | ".join(cells) + " |")
    return lines


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
    captures = read_captures(scratch)
    columns = list(WAIT_FIGURES) + ["segments a response", "octets a segment"]
    lines += ["| Protocol | Server | Rate | " + " | ".join(columns) + " |",
              "|---|---|---|" + "---|" * len(columns)]
    for protocol in protocols:
        for server in servers:
            for rate in sorted(rate for (p, s, rate) in runs if p == protocol and s == server):
                rounds = waits.get((protocol, server, rate))
                cells = [f"{statistics.median(r[name] for r in rounds):.3f}" if rounds else "—"
                         for name in WAIT_FIGURES]
                cells += capture_cells(captures, runs, (protocol, server, rate))
                lines.append(f"| {protocol} | {server} | {rate} | " + " | ".join(cells) + " |")
    lines += turns_table(captures, runs, protocols, servers)
    lines += counts_table(scratch, runs, protocols, servers)
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
        # oha reached 800 req/s of the 1,000, and each figure for a response divides by the 800.
        write_run(scratch, round_, "h2-tls", "a", 1000, 800, 5, {"200": 10})
        write_run(scratch, round_, "h2-tls", "b", 1000, 1000, 4, {"200": 10})
        # 101 runs 0.01 s apart: 100 runs a second. Run i takes i/100 ms, so p50 is 0.50 and p99
        # 0.99, and the warm-up's runs are ten times longer, which the report must discard.
        scale = 10 if warm else 1
        runs = [scale * index / 100 for index in range(101)]
        delays = [0.0] * 100 + [0.5 * round_]
        path = pathlib.Path(scratch, "runs", str(round_), "h2-tls", "a", "1000.waits")
        path.write_text(timehist_lines([0.2] * 101, delays, runs))
        # 11 segments of 120 octets of data 0.01 s apart: 100 a second, one for every eight
        # responses at 800 req/s. The warm-up's segments come ten times as often.
        pcap = pathlib.Path(scratch, "runs", str(round_), "h2-tls", "a", "1000.pcap")
        step = 0.001 if warm else 0.01
        # The client sends its next segment of requests 2 ms after each of the server's segments,
        # so the server answers 8 ms later.
        sent = [(100 + index * step, TEST_PORT, TEST_CLIENT, 120) for index in range(11)]
        asked = [(at + 0.002, TEST_CLIENT, TEST_PORT, 40) for at, _, _, _ in sent]
        pcap.write_bytes(pcap_bytes(sorted(sent + asked)))
        pcap.with_suffix(".port").write_text(f"{TEST_PORT}\n")
        # 2 s of 800 req/s: 1,600 requests. Each takes 30,000 instructions, 20,000 of them the
        # server's own, 10,000 cycles, 6,000 of them its own, and 1.5 system calls, and the server
        # runs half of the time. The warm-up's counts are ten times these.
        counts = pathlib.Path(scratch, "runs", str(round_), "h2-tls", "a", "1000.counts")
        counts.write_text(count_lines(scale, 2.0))
    text = waits_report(scratch)
    assert "| h2-tls | a | 1000 | 100.000 | 0.500 | 0.990 | 1.000 | 0.000 | 0.500 | 0.200 | 0.200 | 0.125 | 120.0 |" in text, text
    # b has no record, and its latency still has its table.
    assert "| h2-tls | b | 1000 | — |" in text and "## h2-tls" in text, text
    assert "| h2-tls | a | 1000 | 30,000.0 | 20,000.0 | 10,000.0 | 6,000.0 | 1.500 | 0.500 |" in text, text
    assert "| h2-tls | b | 1000 | — | — | — | — | — | — |" in text, text
    assert "| h2-tls | a | 1000 | 8.000 | 8.000 | 2.000 | 2.000 |" in text, text
    assert "| h2-tls | b | 1000 | — | — | — | — |" in text.splitlines(), text
    # A count perf did not take, a file with no time and an unknown unit of task-clock give no row.
    assert read_count(count_lines(1, 2.0).replace("9600000,,cycles:u", "<not counted>,,cycles:u")) is None
    assert read_count(count_lines(1, 0.0)) is None
    assert read_count(count_lines(1, 2.0).replace(",msec,", ",hours,")) is None
    assert read_timehist(TIMEHIST_HEAD) is None
    # A segment with no data, such as an acknowledgment, counts for nothing.
    assert read_capture(capture_bytes(3, 0.5, 0)) is None
    test_turns()


# The server's port and two clients' ports in the test's capture of both directions.
TEST_PORT, TEST_CLIENT, TEST_OTHER = 443, 5001, 5002


def test_turns():
    request = lambda at, client: (at, client, TEST_PORT, 40)
    answer = lambda at, client: (at, TEST_PORT, client, 60)
    packets = [
        # The first client: two segments of requests, an acknowledgment, and two of answers. The
        # answer took 0.3 ms from the first request, and the next request 0.1 ms from the first
        # answer.
        request(100.0000, TEST_CLIENT), request(100.0001, TEST_CLIENT),
        (100.00015, TEST_PORT, TEST_CLIENT, 0),
        # The other client's turns lie between the first one's: 0.5 ms and 0.3 ms.
        request(100.0002, TEST_OTHER),
        answer(100.0003, TEST_CLIENT), answer(100.00035, TEST_CLIENT),
        request(100.0004, TEST_CLIENT),
        answer(100.0007, TEST_OTHER),
        # The first client's second answer took 0.4 ms, and its next request 0.2 ms.
        answer(100.0008, TEST_CLIENT),
        request(100.0010, TEST_CLIENT), request(100.0010, TEST_OTHER),
    ]
    figures = read_capture(pcap_bytes(packets), TEST_PORT)
    turns = {name: round(figures[name], 6) for name in TURN_COLUMNS}
    assert turns == {"answer p50": 0.4, "answer mean": 0.4, "next request p50": 0.2,
                     "next request mean": 0.2}, turns
    # Only the server's four segments with data count as its segments: 3 spans in 0.5 ms.
    assert round(figures["segments a second"]) == 6000 and figures["octets a segment"] == 60, figures
    # With no port the capture holds no turns, and every segment with data is the server's.
    assert TURN_COLUMNS[0] not in read_capture(pcap_bytes(packets))
    # A capture of one direction holds no turn.
    assert TURN_COLUMNS[0] not in read_capture(pcap_bytes([p for p in packets if p[1] == TEST_PORT]), TEST_PORT)


def count_lines(scale, seconds):
    """A `perf stat -x,` file of `seconds` of the test's server at 800 req/s, `scale` times over."""
    requests = 800 * seconds * scale
    nanoseconds = seconds * NANOSECONDS_PER_SECOND
    return ("# started on a test\n\n"
            f"{20000 * requests:.0f},,instructions:u,1,100.00,,\n{10000 * requests:.0f},,instructions:k,1,100.00,,\n"
            f"{6000 * requests:.0f},,cycles:u,1,100.00,,\n{4000 * requests:.0f},,cycles:k,1,100.00,,\n"
            f"{nanoseconds / 2 / 1e6:.6f},msec,task-clock,1,100.00,,\n"
            f"{1.5 * requests:.0f},,raw_syscalls:sys_enter,1,100.00,,\n"
            f"{nanoseconds:.0f},ns,duration_time,{nanoseconds:.0f},100.00,,\n")


def pcap_bytes(packets):
    """A pcap on Ethernet of IPv4 TCP packets, each (time, source port, destination port, octets
    of data), holding the heads alone."""
    data = struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 96, 1)
    for at, source, destination, payload in packets:
        ip_header_len, tcp_header_len = 20, 32
        ip = bytes([0x45, 0]) + struct.pack(">H", ip_header_len + tcp_header_len + payload) + bytes(16)
        tcp = struct.pack(">HH", source, destination) + bytes(8) + bytes([(tcp_header_len // 4) << 4])
        head = bytes(14) + ip + tcp + bytes(tcp_header_len - 13)
        data += struct.pack("<IIII", int(at), round((at % 1) * US), len(head), len(head) + payload) + head
    return data


def capture_bytes(count, step, payload):
    """A pcap of `count` segments of the server with `payload` octets of data each, `step` seconds
    apart."""
    return pcap_bytes([(100 + index * step, TEST_PORT, TEST_CLIENT, payload) for index in range(count)])


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
