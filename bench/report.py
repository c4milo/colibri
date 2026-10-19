#!/usr/bin/env python3
"""The report of bench/run.sh (design §8 step 13a): per-unit counts from perf stat and h2load, each
input's median and spread over the rounds, and with a base, the change's ratio to it. An input
loses when the change costs more than the base past the noise, the larger of the two spreads and
the floor, and a loss makes the run fail (decision 33 as amended on 2026-09-30). The report has one
block for each protocol of the run, h11, then h2, then h3, and each block has the tables of its
own inputs.

    report.py <scratch> <report.md> --many-requests <n> --one-connections <n>
    report.py --test

With --test it runs its own tests, which `tools/ci.sh` runs: each writes the files bench/run.sh
leaves in its scratch directory, with the change costing a known factor of the base, and requires
the verdict and the exit status that factor must produce.
"""
import argparse
import os
import re
import statistics
import subprocess
import sys
import tempfile
import unittest

# The floor of a judge run, for instructions per unit, which the owner set on 2026-09-30 from runs
# of a tree against itself on the runner, whose spreads stayed at or under 0.20%
# (docs/performance.md).
JUDGE_FLOOR = 0.005
# The floor of a filter run: a laptop's CPU time moves by several percent from run to run, so it
# keeps decision 33's "anything under about 5% is noise". BENCH_FLOOR sets either for one run.
FILTER_FLOOR = 0.05
# The variants that are builds of colibri; any other variant of a run is a competitor's server.
COLIBRI_VARIANTS = ("base", "change")
# The order the report lists comparisons in: losses first.
READING_ORDER = {"loses": 0, "within the noise": 1, "wins": 2}
# The rounds before this one are the warm-up, which the report discards.
FIRST_COUNTED_ROUND = 1
# The events a judge run counts, by the names perf stat writes.
JUDGE_EVENTS = ("instructions:u", "instructions:k", "cycles:u", "cycles:k", "task-clock", "raw_syscalls:sys_enter")
# The lines h2load writes about a TLS connection, and the order the report names them in.
H2LOAD_TLS = re.compile(r"^(TLS Protocol|Cipher|Server Temp Key): (.+)$", re.M)
TLS_NAMES = ("TLS Protocol", "Cipher", "Server Temp Key")
# The application protocol h2load names for each run of an h2 input: h2 over TLS and h2c in
# cleartext (RFC 9113 §3). An h3 input's runs name h3, the ALPN token of RFC 9114 §3.2.
H2LOAD_PROTOCOL = re.compile(r"^Application protocol: (\S+)$", re.M)
H2_PROTOCOLS = ("h2", "h2c")
H3_PROTOCOLS = ("h3",)
# The blocks of the report in the order it prints them: one for each protocol, with the client that
# sends its load. wrk sends h11 (design §8 step 13g), h2load sends h2, and an h2load built with
# HTTP/3 sends h3 (design §8 step 13d).
REPORT_BLOCKS = (("h11", "wrk"), ("h2", "h2load"), ("h3", "h2load with HTTP/3"))
# wrk's report of an h11 input (design §8 step 13g): the requests it counted, the answers outside
# 2xx and 3xx, and its socket errors. wrk speaks h11 alone.
WRK_REQUESTS = re.compile(r"^\s*(\d+) requests in ", re.M)
WRK_COMMAND = re.compile(r"^load: wrk(.*)$", re.M)
WRK_REJECTED = re.compile(r"^\s*Non-2xx or 3xx responses: (\d+)$", re.M)
WRK_SOCKET_ERRORS = re.compile(r"^\s*Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)$", re.M)
H2LOAD_REQUESTS = re.compile(r"requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded, (\d+) failed, (\d+) errored, (\d+) timeout")
# The nanoseconds in one unit of task-clock, by the unit perf stat writes beside it: perf 6.17
# writes nanoseconds and no unit, and earlier versions milliseconds as "msec".
TASK_CLOCK_NANOSECONDS = {"": 1.0, "ns": 1.0, "nsec": 1.0, "usec": 1e3, "msec": 1e6}
# The lines of a server's log the report prints when a load against it failed.
SERVER_LOG_LINES = 20
NANOSECONDS_PER_SECOND = 1e9


def read_counts(path):
    """The counts a perf stat -x, file holds, by event, or the nanoseconds a filter run wrote."""
    counts = {}
    for line in open(path):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.strip().split(",")
        value, unit, event = fields[0], fields[1], fields[2]
        if value.startswith("<"):
            sys.exit(f"report.py: {path}: perf did not count {event}: {value}")
        counts[event] = float(value)
        if event == "task-clock":
            if unit not in TASK_CLOCK_NANOSECONDS:
                sys.exit(f"report.py: {path}: task-clock in an unknown unit: {unit!r}")
            counts[event] *= TASK_CLOCK_NANOSECONDS[unit]
    return counts


def read_wrk_requests(path, input_name):
    """The requests wrk's report in `path` counted, which fails on an answer outside 2xx and 3xx
    and on a socket error. A server closes each connection of a -one input after its answer, as
    the request's `Connection: close` asks. wrk counts that close as a read error when the answer
    did not say it, so those inputs may have one for each request. load.sh writes the command it
    ran first, and a -one input must ask for the close, and a -many one must not."""
    text = open(path).read()
    counted = WRK_REQUESTS.search(text)
    if counted is None or int(counted.group(1)) == 0:
        sys.exit(f"report.py: {path}: no wrk report with a request")
    requests = int(counted.group(1))
    rejected = WRK_REJECTED.search(text)
    errors = WRK_SOCKET_ERRORS.search(text)
    connect, read, write, timeout = (int(value) for value in errors.groups()) if errors else (0, 0, 0, 0)
    one = input_name.endswith("-one")
    command = WRK_COMMAND.search(text)
    if command is None or ("Connection: close" in command.group(1)) != one:
        sys.exit(f"report.py: {path}: the load for {input_name} ran {command.group(0) if command else 'no wrk command'}")
    read_allowed = requests if one else 0
    if rejected or connect or write or timeout or read > read_allowed:
        print_server_log(path)
        sys.exit(f"report.py: {path}: wrk: {requests} requests, {rejected.group(1) if rejected else 0} "
                 f"outside 2xx and 3xx, socket errors connect {connect}, read {read}, write {write}, timeout {timeout}")
    return requests


def read_requests(path):
    """The requests h2load's reports in `path` say succeeded, which fails on any that did not."""
    succeeded = 0
    runs = H2LOAD_REQUESTS.findall(open(path).read())
    if not runs:
        sys.exit(f"report.py: {path}: no h2load report")
    for total, _, _, ok, failed, errored, timeout in runs:
        if int(ok) != int(total) or int(failed) or int(errored) or int(timeout):
            print_server_log(path)
            sys.exit(f"report.py: {path}: h2load: {ok} of {total} succeeded, {failed} failed, "
                     f"{errored} errored, {timeout} timed out")
        succeeded += int(ok)
    return succeeded


def is_h11(input_name):
    return input_name.startswith("h11-")


def is_h3(input_name):
    return input_name.startswith("h3-")


def protocol_of(input_name):
    """The protocol of an input: h11 or h3 when its name starts with that protocol, and h2
    otherwise. check_protocol requires the input's load to speak it, and the report prints the
    input in that protocol's block."""
    return "h11" if is_h11(input_name) else "h3" if is_h3(input_name) else "h2"


def check_protocol(path, input_name):
    """Fails unless `path` holds the reports of the tool `input_name` takes, speaking its version:
    wrk for an h11 input, h2load speaking h2 for an h2 one, and h2load speaking h3 for an h3 one.
    Every TCP server here speaks h11 and h2, so a load sent in the wrong version would pass unseen
    otherwise."""
    text = open(path).read()
    protocol = protocol_of(input_name)
    if protocol == "h11":
        if WRK_REQUESTS.search(text) is None or H2LOAD_REQUESTS.search(text) is not None:
            sys.exit(f"report.py: {path}: no wrk report for {input_name}")
        return
    spoken = set(H2LOAD_PROTOCOL.findall(text))
    if not spoken or not spoken <= set(H3_PROTOCOLS if protocol == "h3" else H2_PROTOCOLS):
        sys.exit(f"report.py: {path}: h2load spoke {', '.join(sorted(spoken)) or 'no protocol'} for {input_name}")


def print_server_log(h2load_path):
    """Prints the end of the log bench/run.sh kept beside a measurement's h2load reports."""
    server_log = h2load_path.removesuffix(".h2load") + ".server"
    if os.path.exists(server_log):
        lines = open(server_log, errors="replace").read().splitlines()[-SERVER_LOG_LINES:]
        print(f"report.py: {server_log} ends:", *lines, sep="\n", file=sys.stderr)


def number(value):
    """A value as the report prints it: one decimal from 100 up, and three below, so that a count
    of a few system calls per request keeps its digits."""
    return f"{value:,.1f}" if abs(value) >= 100 else f"{value:,.3f}"


def read_tls(path):
    """The protocol, cipher suite and key exchange h2load's reports in `path` name, or None."""
    found = {}
    for name, value in H2LOAD_TLS.findall(open(path).read()):
        found.setdefault(name, value.strip())
    return ", ".join(found[name] for name in TLS_NAMES if name in found) or None


def runs_tls(input_name):
    """Whether an input's connections run TLS: the TCP inputs named for it, and every h3 one."""
    return "-tls-" in input_name or is_h3(input_name)


def per_unit(counts, units, mode):
    """The metrics of one measurement, per request or per connection."""
    if mode == "filter":
        return {"cpu_nanoseconds": counts["cpu_nanoseconds"] / units}
    missing = [event for event in JUDGE_EVENTS if event not in counts]
    if missing:
        sys.exit(f"report.py: perf counted no {', '.join(missing)}")
    return {
        "instructions": (counts["instructions:u"] + counts["instructions:k"]) / units,
        "user_instructions": counts["instructions:u"] / units,
        "cycles": (counts["cycles:u"] + counts["cycles:k"]) / units,
        "system_calls": counts["raw_syscalls:sys_enter"] / units,
        # task-clock is the time the server's threads ran, which read_counts gives in nanoseconds.
        "cpu_nanoseconds": counts["task-clock"] / units,
    }


def summarize(values):
    median = statistics.median(values)
    spread = (max(values) - min(values)) / median if median else 0.0
    return median, spread


def compare(summary, variant, against, primary, floor):
    """The ratio of `variant`'s primary metric to `against`'s, the noise, the larger of the two
    spreads and the floor, and the reading: "loses" when `variant` costs more past the noise,
    "wins" when it costs less, and "within the noise" otherwise."""
    (other, other_spread), (value, value_spread) = summary[against][primary], summary[variant][primary]
    ratio = value / other
    noise = max(other_spread, value_spread, floor)
    reading = "loses" if ratio > 1 + noise else "wins" if ratio < 1 - noise else "within the noise"
    return ratio, noise, reading


def read_samples(arguments, mode):
    """The metrics of each counted round, by variant and input, and the TLS parameters that each
    variant's h2load reports name."""
    samples, tls = {}, {}
    for line in open(os.path.join(arguments.scratch, "records.csv")):
        variant, input_name, round_text, perf_path, h2load_path = line.strip().split(",")
        if int(round_text) < FIRST_COUNTED_ROUND:
            continue
        check_protocol(h2load_path, input_name)
        if is_h11(input_name):
            # wrk counts for a time, so its count is the units.
            units = read_wrk_requests(h2load_path, input_name)
        else:
            units = read_requests(h2load_path)
            expected = arguments.many_requests if input_name.endswith("-many") else arguments.one_connections
            if units != expected:
                sys.exit(f"report.py: {h2load_path}: {units} units where {expected} were planned")
        samples.setdefault((variant, input_name), []).append(per_unit(read_counts(perf_path), units, mode))
        if runs_tls(input_name) and not is_h11(input_name):
            tls.setdefault(variant, set()).add(read_tls(h2load_path) or "h2load named no TLS parameters")
    return samples, tls


def protocol_block(protocol, client, inputs, samples, variants, primary, floor):
    """The lines of the block for `protocol`, whose load `client` sends, with the tables of `inputs`
    alone, and the verdict of each input that the base and the change both ran."""
    competitors = [v for v in variants if v not in COLIBRI_VARIANTS]
    rows, verdicts, standings, rates = [], [], [], []
    for input_name in inputs:
        unit = "request" if input_name.endswith("-many") else "connection"
        summary = {}
        for variant in variants:
            # A competitor that does not serve this input, as http.zig serves no TLS and nginx no
            # h3, has no runs.
            runs = samples.get((variant, input_name))
            if not runs:
                continue
            summary[variant] = {metric: summarize([run[metric] for run in runs]) for metric in runs[0]}
            cells = " | ".join(f"{number(summary[variant][m][0])} ({summary[variant][m][1] * 100:.2f}%)" for m in summary[variant])
            rows.append(f"| {input_name} | {unit} | {variant} | {len(runs)} | {cells} |")
        if unit == "connection":
            # Design §11.2's handshakes per second: what one core completes when its CPU is the limit.
            rates += [f"| {input_name} | {variant} | {number(NANOSECONDS_PER_SECOND / summary[variant]['cpu_nanoseconds'][0])} |"
                      for variant in summary]
        if "base" in summary and "change" in summary:
            ratio, noise, verdict = compare(summary, "change", "base", primary, floor)
            verdicts.append((verdict, f"| {input_name} | {ratio:.4f} | {noise * 100:.2f}% | {verdict} |"))
        for competitor in (c for c in competitors if c in summary and "change" in summary):
            ratio, noise, reading = compare(summary, "change", competitor, primary, floor)
            standings.append((reading, f"| {input_name} | {competitor} | {ratio:.4f} | {noise * 100:.2f}% | {reading} |"))

    # Every run of a mode has the same metrics.
    metrics = list(next(iter(samples.values()))[0])
    lines = [f"### The {protocol} inputs, which {client} sends", ""]
    if verdicts:
        lines += [f"The change against the base, by {primary} per unit; losses first:", "",
                  "| Input | Change / base | Noise | Verdict |", "| --- | ---: | ---: | --- |"]
        lines += [row for _, row in sorted(verdicts, key=lambda v: READING_ORDER[v[0]])] + [""]
    if standings:
        lines += [f"The change against each competitor, by {primary} per unit; losses first. Decision 31 reports",
                  "where colibri wins, matches and loses, and a competitor's numbers never fail the run:", "",
                  "| Input | Competitor | Change / competitor | Noise | colibri |", "| --- | --- | ---: | ---: | --- |"]
        lines += [row for _, row in sorted(standings, key=lambda v: READING_ORDER[v[0]])] + [""]
    lines += ["Each metric's median over the counted rounds, with its spread:", "",
              "| Input | Unit | Variant | Rounds | " + " | ".join(metrics) + " |",
              "| --- | --- | --- | ---: | " + " | ".join("---:" for _ in metrics) + " |"]
    lines += rows
    if rates:
        lines += ["", "The connections one core of the server completes a second, each with one handshake and one request:",
                  "the reciprocal of the median CPU time per connection.", "",
                  "| Input | Variant | Connections per second |", "| --- | --- | ---: |"] + rates
    return lines, verdicts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scratch")
    parser.add_argument("report")
    parser.add_argument("--many-requests", type=int, required=True)
    parser.add_argument("--one-connections", type=int, required=True)
    arguments = parser.parse_args()
    machine = dict(line.strip().split("=", 1) for line in open(os.path.join(arguments.scratch, "machine.txt")) if "=" in line)
    mode = machine["mode"]
    primary = "cpu_nanoseconds" if mode == "filter" else "instructions"
    floor = float(os.environ.get("BENCH_FLOOR", FILTER_FLOOR if mode == "filter" else JUDGE_FLOOR))

    samples, tls = read_samples(arguments, mode)
    inputs = sorted({key[1] for key in samples})
    found = {key[0] for key in samples}
    variants = [v for v in COLIBRI_VARIANTS if v in found] + sorted(found - set(COLIBRI_VARIANTS))
    lines = ["## bench/run.sh", ""]
    lines += [f"- {key}: {value}" for key, value in machine.items()]
    lines += [f"- tls, {variant}: {'; '.join(sorted(tls[variant]))}" for variant in variants if variant in tls]
    lines += [f"- floor: {floor * 100:.2f}%"]
    verdicts = []
    for protocol, client in REPORT_BLOCKS:
        protocol_inputs = [input_name for input_name in inputs if protocol_of(input_name) == protocol]
        # A protocol with no input in the run has no block.
        if not protocol_inputs:
            continue
        block, protocol_verdicts = protocol_block(protocol, client, protocol_inputs, samples, variants, primary, floor)
        lines += [""] + block
        verdicts += protocol_verdicts
    with open(arguments.report, "w") as report:
        report.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    if any(verdict == "loses" for verdict, _ in verdicts):
        sys.exit("report.py: an input loses past the noise")


# Tests.

TEST_UNITS = {"h2-many": 20000, "h2-tls-one": 640}
# The h3 input and the h11 input that a test run has when it asks for each. wrk counts the requests
# it finished, which are the h11 input's units.
TEST_H3_UNITS = {"h3-many": 20000}
TEST_H11_UNITS = {"h11-many": 20000}
TEST_INSTRUCTIONS_PER_UNIT = {"h2-many": 50000.0, "h2-tls-one": 900000.0, "h3-many": 150000.0, "h11-many": 40000.0}
# The command a test run's wrk report starts with, as load.sh writes it for an input of many
# requests.
TEST_WRK_COMMAND = "load: wrk http://127.0.0.1:18480/\n"
# The heading of each block, in the order the report prints them.
TEST_HEADINGS = ("### The h11 inputs, which wrk sends", "### The h2 inputs, which h2load sends",
                 "### The h3 inputs, which h2load with HTTP/3 sends")
# The connections one run of h2load opens on an input that has one request on each.
TEST_ONE_CLIENTS = 16
# The floor the tests pass in BENCH_FLOOR, which the expected verdicts assume.
TEST_FLOOR = 0.05
# The nanoseconds the server runs a unit in, before a round's factor.
TEST_NANOSECONDS_PER_UNIT = 4000
# What h2load writes about a TLS connection, before its count of requests.
TEST_TLS = "TLS Protocol: TLSv1.3\nCipher: {cipher}\nServer Temp Key: X25519 253 bits\n"
# A wrk report, with the lines of its errors where `errors` stands.
TEST_WRK = ("Running 2s test @ http://127.0.0.1:18480/\n  2 threads and 16 connections\n"
            "  {requests} requests in 2.00s, 8.00MB read\n{errors}Requests/sec:  50000.00\n")
# Each round's factor on every count. Round 0 is the warm-up and costs half as much again, as a
# first round can, so that a report that counts it shows a spread past the floor.
TEST_ROUND_FACTORS = (1.5, 1.004, 0.997, 1.002, 0.999, 1.001)


def write_test_run(directory, change_factor, changed_inputs=tuple(TEST_UNITS), failed_request=False, mode="judge", kernel_only=False,
                   change_cipher="TLS_AES_256_GCM_SHA384", task_clock_unit="msec", competitors=None, with_base=True,
                   change_protocol=None, served=None, h3=False, h11=False):
    """Writes the files a run of bench/run.sh leaves, with the change costing `change_factor` times
    the base on each input in `changed_inputs`: in the server's user and kernel instructions both,
    or with `kernel_only` in the kernel's alone, as a change that adds system calls costs. The base
    runs TLS_AES_256_GCM_SHA384 on its TLS input, and the change runs `change_cipher`. The server
    runs TEST_NANOSECONDS_PER_UNIT a unit, which perf writes in `task_clock_unit`. Each competitor
    in `competitors` costs its factor times the base, and with `with_base` false no base runs. Each
    run speaks h2 over TLS, h2c in cleartext and h3 on an h3 input, and the change
    `change_protocol` if one is given. A variant that `served` names runs only the inputs it lists
    there. With `h3` the run has TEST_H3_UNITS' inputs too, and with `h11` TEST_H11_UNITS' inputs,
    whose load wrk sends."""
    factors = dict(competitors or {})
    units_of = dict(TEST_UNITS, **(TEST_H3_UNITS if h3 else {}), **(TEST_H11_UNITS if h11 else {}))
    if with_base:
        factors["base"] = 1.0
    with open(os.path.join(directory, "machine.txt"), "w") as machine:
        machine.write(f"mode={mode}\nrounds={len(TEST_ROUND_FACTORS) - 1}\n")
    records = []
    for round_number, round_factor in enumerate(TEST_ROUND_FACTORS):
        for input_name, units in units_of.items():
            for variant in ["change"] + sorted(factors):
                if input_name not in (served or {}).get(variant, (input_name,)):
                    continue
                name = os.path.join(directory, f"{variant}-{input_name}-{round_number}")
                changed = variant == "change" and input_name in changed_inputs
                base_instructions = TEST_INSTRUCTIONS_PER_UNIT[input_name] * units * round_factor * factors.get(variant, 1.0)
                user = base_instructions * 0.7 * (change_factor if changed and not kernel_only else 1.0)
                nanoseconds = TEST_NANOSECONDS_PER_UNIT * units * round_factor
                kernel = base_instructions * 0.3 * (change_factor if changed else 1.0)
                instructions = user + kernel
                with open(name + ".perf", "w") as perf:
                    if mode == "filter":
                        perf.write(f"{instructions / 10:.0f},,cpu_nanoseconds\n")
                    else:
                        perf.write(f"# started on a test\n\n{user:.0f},,instructions:u,1,100.00,,\n")
                        perf.write(f"{kernel:.0f},,instructions:k,1,100.00,,\n")
                        perf.write(f"{instructions:.0f},,cycles:u,1,100.00,,\n{instructions / 4:.0f},,cycles:k,1,100.00,,\n")
                        if task_clock_unit == "msec":
                            perf.write(f"{nanoseconds / 1e6:.6f},msec,task-clock,1,100.00,,\n")
                        else:
                            perf.write(f"{nanoseconds:.0f},,task-clock,{nanoseconds:.0f},100.00,,\n")
                        perf.write(f"{units * 4},,raw_syscalls:sys_enter,1,100.00,,\n")
                failed = 1 if failed_request and changed and round_number == 3 else 0
                with open(name + ".server", "w") as server_log:
                    server_log.write("http-server: listening\n" + ("http-server: assertion failed\n" if failed else ""))
                per_run = units if input_name.endswith("-many") else TEST_ONE_CLIENTS
                cipher = change_cipher if variant == "change" else "TLS_AES_256_GCM_SHA384"
                with open(name + ".h2load", "w") as h2load:
                    if is_h11(input_name):
                        rejected = f"  Non-2xx or 3xx responses: {failed}\n" if failed else ""
                        h2load.write(TEST_WRK_COMMAND + TEST_WRK.format(requests=units, errors=rejected))
                    else:
                        for run in range(units // per_run):
                            if runs_tls(input_name):
                                h2load.write(TEST_TLS.format(cipher=cipher))
                            protocol = "h3" if is_h3(input_name) else "h2" if "-tls-" in input_name else "h2c"
                            if variant == "change" and change_protocol:
                                protocol = change_protocol
                            h2load.write(f"Application protocol: {protocol}\n")
                            lost = failed if run == 0 else 0
                            h2load.write(f"requests: {per_run} total, {per_run} started, {per_run} done, "
                                         f"{per_run - lost} succeeded, {lost} failed, 0 errored, 0 timeout\n")
                records.append(f"{variant},{input_name},{round_number},{name}.perf,{name}.h2load\n")
    with open(os.path.join(directory, "records.csv"), "w") as records_file:
        records_file.writelines(records)


class Verdicts(unittest.TestCase):
    def report(self, change_factor, floor=TEST_FLOOR, **options):
        """report.py's exit status and output on a run with the change costing `change_factor`,
        under `floor`, or under the mode's own floor when `floor` is None."""
        environment = {name: value for name, value in os.environ.items() if name != "BENCH_FLOOR"}
        if floor is not None:
            environment["BENCH_FLOOR"] = str(floor)
        with tempfile.TemporaryDirectory() as directory:
            write_test_run(directory, change_factor, **options)
            result = subprocess.run([sys.executable, os.path.abspath(__file__), directory, os.path.join(directory, "report.md"),
                                     "--many-requests", str(TEST_UNITS["h2-many"]), "--one-connections", str(TEST_UNITS["h2-tls-one"])],
                                    capture_output=True, text=True, env=environment)
            return result.returncode, result.stdout + result.stderr

    def test_a_tree_against_itself_is_within_the_noise(self):
        status, output = self.report(1.0)
        self.assertEqual(status, 0, output)
        self.assertIn("| h2-many | 1.0000 | 5.00% | within the noise |", output)
        # Four system calls per unit, printed with the digits a small count needs.
        self.assertIn(" | 4.000 (0.00%) | ", output)

    def test_a_cost_past_the_floor_loses_and_fails_the_run(self):
        status, output = self.report(1.10)
        self.assertNotEqual(status, 0, output)
        self.assertIn("| h2-many | 1.1000 | 5.00% | loses |", output)

    def test_a_saving_past_the_floor_wins(self):
        status, output = self.report(0.90)
        self.assertEqual(status, 0, output)
        self.assertIn("| h2-tls-one | 0.9000 | 5.00% | wins |", output)

    def test_a_cost_inside_the_floor_is_within_the_noise(self):
        status, output = self.report(1.04)
        self.assertEqual(status, 0, output)
        self.assertIn("| h2-tls-one | 1.0400 | 5.00% | within the noise |", output)

    def test_a_cost_in_the_kernel_loses(self):
        status, output = self.report(1.5, kernel_only=True)
        self.assertNotEqual(status, 0, output)
        self.assertIn("| h2-many | 1.1500 | 5.00% | loses |", output)

    def test_a_loss_is_listed_first(self):
        status, output = self.report(1.10, changed_inputs=("h2-tls-one",))
        self.assertNotEqual(status, 0, output)
        self.assertIn("| --- | ---: | ---: | --- |\n| h2-tls-one | 1.1000 | 5.00% | loses |\n", output)

    def test_a_failed_request_refuses_the_run(self):
        status, output = self.report(1.0, failed_request=True)
        self.assertNotEqual(status, 0, output)
        self.assertIn("h2load: 19999 of 20000 succeeded, 1 failed", output)
        self.assertIn("http-server: assertion failed", output)

    def test_a_report_names_the_cipher_suite_each_build_ran(self):
        status, output = self.report(1.0, change_cipher="TLS_CHACHA20_POLY1305_SHA256")
        self.assertEqual(status, 0, output)
        self.assertIn("- tls, base: TLSv1.3, TLS_AES_256_GCM_SHA384, X25519 253 bits\n", output)
        self.assertIn("- tls, change: TLSv1.3, TLS_CHACHA20_POLY1305_SHA256, X25519 253 bits\n", output)

    def test_perf_writes_task_clock_in_either_unit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "run.perf")
            for line in ("235127125,,task-clock,235127125,100.00,0.997,CPUs utilized",
                         "235.127125,msec,task-clock,235127125,100.00,0.997,CPUs utilized"):
                with open(path, "w") as perf:
                    perf.write(line + "\n")
                self.assertAlmostEqual(read_counts(path)["task-clock"], 235127125.0, places=3)
            with open(path, "w") as perf:
                perf.write("235,furlongs,task-clock,235,100.00,,\n")
            with self.assertRaises(SystemExit):
                read_counts(path)

    def test_a_report_gives_cpu_time_in_nanoseconds(self):
        # 4,000 ns a unit times the median round's factor, 1.001, in either unit perf writes.
        for unit in ("msec", ""):
            status, output = self.report(1.0, task_clock_unit=unit)
            self.assertEqual(status, 0, output)
            self.assertIn(" | 4,004.0 (0.70%) |", output)

    def test_a_report_gives_the_connections_a_core_completes_a_second(self):
        # 4,004 ns of CPU a connection, the median round's, is 249,750.2 connections a second.
        status, output = self.report(1.0)
        self.assertEqual(status, 0, output)
        self.assertIn("| h2-tls-one | change | 249,750.2 |\n", output)
        self.assertIn("| h2-tls-one | base | 249,750.2 |\n", output)
        # An input counted per request has no such row.
        self.assertNotIn("| h2-many | change | 249,750.2 |", output)

    def test_each_mode_has_its_own_floor(self):
        status, output = self.report(1.0, floor=None)
        self.assertEqual(status, 0, output)
        self.assertIn("- floor: 0.50%\n", output)
        # The rounds of the test runs spread by 0.70%, which is then the noise.
        self.assertIn("| h2-many | 1.0000 | 0.70% | within the noise |", output)
        status, output = self.report(1.0, floor=None, mode="filter")
        self.assertEqual(status, 0, output)
        self.assertIn("- floor: 5.00%\n", output)

    def test_competitors_are_reported_and_never_fail_the_run(self):
        # nginx costs half what colibri does and h2o twice, with no base built.
        status, output = self.report(1.0, competitors={"nginx": 0.5, "h2o": 2.0}, with_base=False)
        self.assertEqual(status, 0, output)
        self.assertNotIn("The change against the base", output)
        self.assertIn("| --- | --- | ---: | ---: | --- |\n| h2-many | nginx | 2.0000 | 5.00% | loses |\n", output)
        self.assertIn("| h2-many | h2o | 0.5000 | 5.00% | wins |", output)
        self.assertIn("| h2-tls-one | connection | nginx | 5 | ", output)

    def test_an_input_whose_load_spoke_another_version_refuses_the_run(self):
        # An h2 input that h2load sent as h11, as a load script that lost its version would.
        status, output = self.report(1.0, change_protocol="http/1.1")
        self.assertNotEqual(status, 0, output)
        self.assertIn("h2load spoke http/1.1 for h2-", output)

    @staticmethod
    def written(text):
        with tempfile.NamedTemporaryFile("w", suffix=".h2load", delete=False) as held:
            held.write(text)
        return held.name

    def test_an_h2_input_takes_h2load_and_an_h11_input_wrk(self):
        h2load = self.written("Application protocol: h2\nrequests: 1 total, 1 started, 1 done, 1 succeeded, 0 failed, 0 errored, 0 timeout\n")
        wrk = self.written(TEST_WRK.format(requests=100, errors=""))
        check_protocol(h2load, "h2-tls-one")
        check_protocol(wrk, "h11-tls-one")
        for path, input_name in ((h2load, "h11-many"), (wrk, "h2-many")):
            with self.assertRaises(SystemExit):
                check_protocol(path, input_name)
        # An h2 report that names no protocol proves nothing.
        empty = self.written("requests: 1 total\n")
        with self.assertRaises(SystemExit):
            check_protocol(empty, "h2-many")
        for path in (h2load, wrk, empty):
            os.unlink(path)

    def test_an_h3_input_takes_h2load_speaking_h3(self):
        h3 = self.written("Application protocol: h3\nrequests: 1 total, 1 started, 1 done, 1 succeeded, 0 failed, 0 errored, 0 timeout\n")
        h2 = self.written("Application protocol: h2\nrequests: 1 total, 1 started, 1 done, 1 succeeded, 0 failed, 0 errored, 0 timeout\n")
        check_protocol(h3, "h3-one")
        for path, input_name in ((h2, "h3-one"), (h3, "h2-tls-one")):
            with self.assertRaises(SystemExit):
                check_protocol(path, input_name)
        for path in (h3, h2):
            os.unlink(path)

    def test_wrk_counts_its_requests_and_refuses_errors(self):
        close = "load: wrk -H Connection: close http://127.0.0.1:18480/\n"
        keep = "load: wrk http://127.0.0.1:18480/\n"
        cases = (
            (keep, "", "h11-many", 100),
            (close, "  Socket errors: connect 0, read 100, write 0, timeout 0\n", "h11-one", 100),
            (close, "", "h11-one", 100),
            (keep, "", "h11-one", None),
            (close, "", "h11-many", None),
            ("", "", "h11-many", None),
            (keep, "  Socket errors: connect 0, read 1, write 0, timeout 0\n", "h11-many", None),
            (close, "  Socket errors: connect 0, read 101, write 0, timeout 0\n", "h11-one", None),
            (close, "  Socket errors: connect 1, read 100, write 0, timeout 0\n", "h11-one", None),
            (keep, "  Socket errors: connect 0, read 0, write 0, timeout 1\n", "h11-many", None),
            (keep, "  Non-2xx or 3xx responses: 1\n", "h11-many", None),
        )
        for command, errors, input_name, wanted in cases:
            path = self.written(command + TEST_WRK.format(requests=100, errors=errors))
            if wanted is None:
                with self.assertRaises(SystemExit, msg=command + errors):
                    read_wrk_requests(path, input_name)
            else:
                self.assertEqual(wanted, read_wrk_requests(path, input_name))
            os.unlink(path)
        # A report that counted no request measured nothing.
        path = self.written(keep + TEST_WRK.format(requests=0, errors=""))
        with self.assertRaises(SystemExit):
            read_wrk_requests(path, "h11-many")
        os.unlink(path)

    def test_a_competitor_that_serves_some_inputs_is_compared_on_those_alone(self):
        # http.zig serves no TLS, so it runs h2-many alone here, and nginx runs both.
        status, output = self.report(1.0, competitors={"nginx": 1.0, "httpz": 0.5}, with_base=False,
                                     served={"httpz": ("h2-many",)})
        self.assertEqual(status, 0, output)
        self.assertIn("| h2-many | httpz | 2.0000 | 5.00% | loses |", output)
        self.assertNotIn("| h2-tls-one | httpz |", output)
        self.assertNotIn("| h2-tls-one | connection | httpz |", output)
        self.assertIn("| h2-tls-one | nginx | 1.0000 | 5.00% | within the noise |", output)

    def test_an_h3_input_is_judged_and_names_the_suite_its_builds_ran(self):
        # The h3 input alone costs more.
        status, output = self.report(1.10, changed_inputs=("h3-many",), h3=True)
        self.assertNotEqual(status, 0, output)
        self.assertIn("| h3-many | 1.1000 | 5.00% | loses |", output)
        self.assertIn("| h2-many | 1.0000 | 5.00% | within the noise |", output)
        self.assertIn("| h3-many | request | change | 5 | ", output)
        # Every h3 connection runs TLS, so its parameters are read as a TLS input's are.
        self.assertTrue(runs_tls("h3-many") and runs_tls("h3-one") and runs_tls("h2-tls-one"))
        self.assertFalse(runs_tls("h2-many") or runs_tls("h2-one"))
        # A build that runs the h3 input alone names the suite from the h3 runs' reports.
        status, output = self.report(1.0, with_base=False, h3=True, served={"change": tuple(TEST_H3_UNITS)})
        self.assertEqual(status, 0, output)
        self.assertIn("- tls, change: TLSv1.3, TLS_AES_256_GCM_SHA384, X25519 253 bits\n", output)

    def test_a_competitor_is_compared_on_the_inputs_it_ran(self):
        # nginx runs no h3 input and quic-go no h2 one.
        ran = {"nginx": tuple(TEST_UNITS), "quic-go": tuple(TEST_H3_UNITS)}
        status, output = self.report(1.0, competitors={"nginx": 0.5, "quic-go": 2.0}, with_base=False, h3=True, served=ran)
        self.assertEqual(status, 0, output)
        self.assertIn("| h2-many | nginx | 2.0000 | 5.00% | loses |", output)
        self.assertIn("| h3-many | quic-go | 0.5000 | 5.00% | wins |", output)
        self.assertNotIn("| h3-many | nginx |", output)
        self.assertNotIn("| h2-many | quic-go |", output)
        self.assertNotIn("| h3-many | request | nginx |", output)

    @staticmethod
    def blocks(output):
        """The heading of each block in `output`, in its order, with the inputs that the rows of the
        block's tables name."""
        found, heading = {}, None
        for line in output.splitlines():
            if line.startswith("### "):
                heading = line
                found[heading] = set()
            elif heading is not None and re.match(r"\| h\d", line):
                found[heading].add(line.split(" | ")[0].removeprefix("| "))
        return found

    def test_the_blocks_come_in_the_order_h11_h2_h3(self):
        status, output = self.report(1.0, h11=True, h3=True)
        self.assertEqual(status, 0, output)
        self.assertEqual(list(self.blocks(output)), list(TEST_HEADINGS))

    def test_each_input_is_in_the_block_of_its_protocol(self):
        # nginx runs the TCP inputs and quic-go the h3 input, so each block has rows for a competitor too.
        ran = {"nginx": tuple(TEST_UNITS) + tuple(TEST_H11_UNITS), "quic-go": tuple(TEST_H3_UNITS)}
        status, output = self.report(1.0, h11=True, h3=True, competitors={"nginx": 0.5, "quic-go": 2.0}, served=ran)
        self.assertEqual(status, 0, output)
        inputs = ({"h11-many"}, {"h2-many", "h2-tls-one"}, {"h3-many"})
        self.assertEqual(self.blocks(output), dict(zip(TEST_HEADINGS, inputs)))

    def test_a_protocol_with_no_input_has_no_block(self):
        # The run has the h2 inputs alone.
        status, output = self.report(1.0)
        self.assertEqual(status, 0, output)
        self.assertEqual(list(self.blocks(output)), [TEST_HEADINGS[1]])
        # The run has the h3 input alone.
        status, output = self.report(1.0, with_base=False, h3=True, served={"change": tuple(TEST_H3_UNITS)})
        self.assertEqual(status, 0, output)
        self.assertEqual(list(self.blocks(output)), [TEST_HEADINGS[2]])

    def test_a_loss_in_any_block_fails_the_run(self):
        for loser in ("h11-many", "h2-many", "h3-many"):
            status, output = self.report(1.10, changed_inputs=(loser,), h11=True, h3=True)
            self.assertNotEqual(status, 0, output)
            self.assertIn(f"| {loser} | 1.1000 | 5.00% | loses |", output)
            self.assertIn("report.py: an input loses past the noise", output)

    def test_a_filter_run_compares_cpu_time(self):
        status, output = self.report(1.10, mode="filter")
        self.assertNotEqual(status, 0, output)
        self.assertIn("by cpu_nanoseconds per unit", output)
        self.assertIn("| h2-many | 1.1000 | 5.00% | loses |", output)


if __name__ == "__main__":
    if sys.argv[1:] == ["--test"]:
        unittest.main(argv=sys.argv[:1])
    main()
