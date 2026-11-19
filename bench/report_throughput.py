"""The report of bench/run.sh --throughput (design §8 step 13q).

For each input, server and counted round it reads the load tool's own count of requests a second:
h2load's `finished in` line, or wrk's `Requests/sec`. It refuses a load whose requests failed past
those in flight when its time ran out, or that errored, timed out, or got an answer outside 2xx.
It reads the server's CPU time and the load's wall time that run_throughput.sh kept, and their
ratio is how busy the server's core was. Round 0, the warm-up, is not counted.

For each input and server the report gives the median rate and its spread, the median busy share,
and which side was the limit: the server, when its core was busy for BUSY_FULL of the time or
more, and the load tool otherwise, since the server then waited for requests.

    python3 bench/report_throughput.py <scratch> <report.md>
    python3 bench/report_throughput.py --test
"""

import os
import re
import statistics
import sys
import tempfile

# The share of the load's time the server's core must run for the server to be the limit.
BUSY_FULL = 0.95
FIRST_COUNTED_ROUND = 1
H2LOAD_RATE = re.compile(r"finished in [0-9.]+s, ([0-9.]+) req/s")
H2LOAD_REQUESTS = re.compile(r"requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded, (\d+) failed, (\d+) errored, (\d+) timeout")
WRK_RATE = re.compile(r"Requests/sec:\s+([0-9.]+)")
WRK_SOCKET_ERRORS = re.compile(r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)")
# The connections and streams a load holds, which bound the requests its end cuts off.
IN_FLIGHT_MAX = re.compile(r"(\d+) connections, (\d+) streams")


def in_flight_max(machine):
    match = IN_FLIGHT_MAX.search(machine)
    if not match:
        sys.exit("report_throughput.py: machine.txt names no connections and streams")
    return int(match.group(1)) * int(match.group(2))


def rate_of(path, input_name, in_flight):
    """The requests a second the load tool at `path` counted, or exit when its load went wrong."""
    text = open(path).read()
    if input_name.startswith("h11-"):
        if "Non-2xx or 3xx responses" in text:
            sys.exit(f"report_throughput.py: {path}: an answer outside 2xx and 3xx")
        errors = WRK_SOCKET_ERRORS.search(text)
        if errors and any(int(count) for count in errors.groups()):
            sys.exit(f"report_throughput.py: {path}: {errors.group(0)}")
        match = WRK_RATE.search(text)
    else:
        requests = H2LOAD_REQUESTS.search(text)
        if not requests:
            sys.exit(f"report_throughput.py: {path}: h2load reported no requests")
        _, _, _, succeeded, failed, errored, timeout = (int(count) for count in requests.groups())
        # The requests in flight when the time ran out end unanswered, and count as failed.
        if succeeded == 0 or failed > in_flight or errored or timeout:
            sys.exit(f"report_throughput.py: {path}: {requests.group(0)}")
        match = H2LOAD_RATE.search(text)
    if not match:
        sys.exit(f"report_throughput.py: {path}: no count of requests a second")
    return float(match.group(1))


def busy_of(path):
    cpu_ns, wall_ns = (int(field) for field in open(path).read().strip().split(","))
    if wall_ns <= 0:
        sys.exit(f"report_throughput.py: {path}: no wall time")
    return cpu_ns / wall_ns


def read_runs(scratch, in_flight):
    """{(input, variant): [(rate, busy) of each counted round]}, in the order they first ran."""
    runs = {}
    for line in open(os.path.join(scratch, "throughput.csv")):
        variant, input_name, round_text, cpu_path, load_path = line.strip().split(",")
        if int(round_text) < FIRST_COUNTED_ROUND:
            continue
        sample = (rate_of(load_path, input_name, in_flight), busy_of(cpu_path))
        runs.setdefault((input_name, variant), []).append(sample)
    return runs


def spread(values):
    median = statistics.median(values)
    return (max(values) - min(values)) / median if median else 0.0


def report(scratch):
    machine = open(os.path.join(scratch, "machine.txt")).read()
    runs = read_runs(scratch, in_flight_max(machine))
    lines = ["# Throughput at full load (design §8 step 13q)", "", "```text", machine.rstrip(), "```", "",
             "The requests a second each load tool counted, the median of the counted rounds with their "
             "spread, and the share of the load's time the server's threads ran on their core. Under "
             f"{BUSY_FULL:.2f} the server waited for requests, so the load tool was the limit, and the "
             "server serves at least that rate.", ""]
    inputs = list(dict.fromkeys(input_name for input_name, _ in runs))
    for input_name in inputs:
        lines += [f"## {input_name}", "", "| Server | Rounds | Requests a second | Busy | Limit |", "|---|---|---|---|---|"]
        for (name, variant), samples in runs.items():
            if name != input_name:
                continue
            rates = [rate for rate, _ in samples]
            busy = statistics.median(busy for _, busy in samples)
            limit = "server" if busy >= BUSY_FULL else "load"
            lines.append(f"| {variant} | {len(samples)} | {statistics.median(rates):,.1f} ({spread(rates) * 100:.2f}%) "
                         f"| {busy:.2f} | {limit} |")
        lines.append("")
    return "\n".join(lines)


TEST_MACHINE = "mode=judge\nthroughput=10 s a load, 32 connections, 100 streams on each h2 or h3 connection, 2 load threads\n"
TEST_H2LOAD = ("finished in 10.00s, {rate} req/s, 40.00MB/s\n"
               "requests: {total} total, {total} started, {done} done, {succeeded} succeeded, {failed} failed, "
               "{errored} errored, 0 timeout\n")
TEST_WRK = "Running 10s test @ http://127.0.0.1:18480/\n  2 threads and 32 connections\n{errors}Requests/sec: {rate}\n"


def write_test_run(directory, rates, h2load=None, wrk_errors=""):
    """Writes the files a --throughput run leaves: for each (input, variant), the rate and the busy
    share of rounds 0 to 3, round 0 at half the rate."""
    with open(os.path.join(directory, "machine.txt"), "w") as machine:
        machine.write(TEST_MACHINE)
    records = []
    for (input_name, variant), (rate, busy) in rates.items():
        for round_number in range(4):
            name = os.path.join(directory, f"{variant}-{input_name}-{round_number}")
            round_rate = rate / 2 if round_number == 0 else rate * (1 + 0.01 * (round_number - 2))
            with open(name + ".cpu", "w") as cpu:
                cpu.write(f"{int(busy * 1e10)},{int(1e10)}\n")
            with open(name + ".load", "w") as load:
                if input_name.startswith("h11-"):
                    load.write(TEST_WRK.format(rate=round_rate, errors=wrk_errors))
                else:
                    fields = dict(rate=round_rate, total=1000, done=1000, succeeded=1000, failed=0, errored=0)
                    fields.update(h2load or {})
                    load.write(TEST_H2LOAD.format(**fields))
            records.append(f"{variant},{input_name},{round_number},{name}.cpu,{name}.load\n")
    with open(os.path.join(directory, "throughput.csv"), "w") as csv:
        csv.writelines(records)


def run_test(rates, **options):
    with tempfile.TemporaryDirectory() as directory:
        write_test_run(directory, rates, **options)
        try:
            return report(directory)
        except SystemExit as exit_:
            return f"exit: {exit_}"


def test():
    rates = {("h2-many", "change"): (400000.0, 0.62), ("h2-many", "hyper"): (190000.0, 0.99),
             ("h11-many", "change"): (150000.0, 0.97)}
    text = run_test(rates)
    # The median of the counted rounds, 0.99, 1.00 and 1.01 of the rate, and round 0 left out.
    assert "| change | 3 | 400,000.0 (2.00%) | 0.62 | load |" in text, text
    assert "| hyper | 3 | 190,000.0 (2.00%) | 0.99 | server |" in text, text
    assert "## h11-many" in text and "| change | 3 | 150,000.0 (2.00%) | 0.97 | server |" in text, text
    assert text.index("## h2-many") < text.index("## h11-many"), text
    # A load cut at its end leaves its requests in flight failed, which is no fault.
    assert "exit" not in run_test(rates, h2load={"failed": 3200, "succeeded": 996800})
    assert "exit" in run_test(rates, h2load={"failed": 3201, "succeeded": 996799})
    assert "exit" in run_test(rates, h2load={"errored": 1})
    assert "exit" in run_test(rates, h2load={"succeeded": 0})
    assert "exit" in run_test(rates, wrk_errors="  Non-2xx or 3xx responses: 5\n")
    assert "exit" in run_test(rates, wrk_errors="  Socket errors: connect 0, read 2, write 0, timeout 0\n")
    assert "exit" not in run_test(rates, wrk_errors="  Socket errors: connect 0, read 0, write 0, timeout 0\n")
    print("report_throughput.py: ok")


def main(argv):
    if argv[1:] == ["--test"]:
        test()
        return
    if len(argv) != 3:
        sys.exit(__doc__)
    with open(argv[2], "w") as out:
        out.write(report(argv[1]))


if __name__ == "__main__":
    main(sys.argv)
