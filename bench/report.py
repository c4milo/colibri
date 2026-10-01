#!/usr/bin/env python3
"""The report of bench/run.sh (design §8 step 13a): per-unit counts from perf stat and h2load, each
input's median and spread over the rounds, and with a base, the change's ratio to it. An input
loses when the change costs more than the base past the noise, the larger of the two spreads and
the floor, and a loss makes the run fail (decision 33 as amended on 2026-09-30).

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
H2LOAD_REQUESTS = re.compile(r"requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded, (\d+) failed, (\d+) errored, (\d+) timeout")
# The nanoseconds in one unit of task-clock, by the unit perf stat writes beside it: perf 6.17
# writes nanoseconds and no unit, and earlier versions milliseconds as "msec".
TASK_CLOCK_NANOSECONDS = {"": 1.0, "ns": 1.0, "nsec": 1.0, "usec": 1e3, "msec": 1e6}
# The lines of a server's log the report prints when a load against it failed.
SERVER_LOG_LINES = 20


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

    samples, tls = {}, {}
    for line in open(os.path.join(arguments.scratch, "records.csv")):
        variant, input_name, round_text, perf_path, h2load_path = line.strip().split(",")
        if int(round_text) < FIRST_COUNTED_ROUND:
            continue
        units = read_requests(h2load_path)
        expected = arguments.many_requests if input_name.endswith("-many") else arguments.one_connections
        if units != expected:
            sys.exit(f"report.py: {h2load_path}: {units} units where {expected} were planned")
        samples.setdefault((variant, input_name), []).append(per_unit(read_counts(perf_path), units, mode))
        if "-tls-" in input_name:
            tls.setdefault(variant, set()).add(read_tls(h2load_path) or "h2load named no TLS parameters")

    inputs = sorted({key[1] for key in samples})
    found = {key[0] for key in samples}
    variants = [v for v in COLIBRI_VARIANTS if v in found] + sorted(found - set(COLIBRI_VARIANTS))
    competitors = [v for v in variants if v not in COLIBRI_VARIANTS]
    rows, verdicts, standings = [], [], []
    for input_name in inputs:
        unit = "request" if input_name.endswith("-many") else "connection"
        summary = {}
        for variant in variants:
            runs = samples[(variant, input_name)]
            summary[variant] = {metric: summarize([run[metric] for run in runs]) for metric in runs[0]}
            cells = " | ".join(f"{number(summary[variant][m][0])} ({summary[variant][m][1] * 100:.2f}%)" for m in summary[variant])
            rows.append(f"| {input_name} | {unit} | {variant} | {len(runs)} | {cells} |")
        if "base" in summary and "change" in summary:
            ratio, noise, verdict = compare(summary, "change", "base", primary, floor)
            verdicts.append((verdict, f"| {input_name} | {ratio:.4f} | {noise * 100:.2f}% | {verdict} |"))
        for competitor in competitors:
            ratio, noise, reading = compare(summary, "change", competitor, primary, floor)
            standings.append((reading, f"| {input_name} | {competitor} | {ratio:.4f} | {noise * 100:.2f}% | {reading} |"))

    metrics = list(samples[(variants[0], inputs[0])][0])
    lines = ["## bench/run.sh", ""]
    lines += [f"- {key}: {value}" for key, value in machine.items()]
    lines += [f"- tls, {variant}: {'; '.join(sorted(tls[variant]))}" for variant in variants if variant in tls]
    lines += [f"- floor: {floor * 100:.2f}%", ""]
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
    with open(arguments.report, "w") as report:
        report.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    if any(verdict == "loses" for verdict, _ in verdicts):
        sys.exit("report.py: an input loses past the noise")


# Tests.

TEST_UNITS = {"h2-many": 20000, "h2-tls-one": 640}
TEST_INSTRUCTIONS_PER_UNIT = {"h2-many": 50000.0, "h2-tls-one": 900000.0}
# The floor the tests pass in BENCH_FLOOR, which the expected verdicts assume.
TEST_FLOOR = 0.05
# The nanoseconds the server runs a unit in, before a round's factor.
TEST_NANOSECONDS_PER_UNIT = 4000
# What h2load writes about a TLS connection, before its count of requests.
TEST_TLS = "TLS Protocol: TLSv1.3\nCipher: {cipher}\nServer Temp Key: X25519 253 bits\nApplication protocol: h2\n"
# Each round's factor on every count. Round 0 is the warm-up and costs half as much again, as a
# first round can, so that a report that counts it shows a spread past the floor.
TEST_ROUND_FACTORS = (1.5, 1.004, 0.997, 1.002, 0.999, 1.001)


def write_test_run(directory, change_factor, changed_inputs=tuple(TEST_UNITS), failed_request=False, mode="judge", kernel_only=False,
                   change_cipher="TLS_AES_256_GCM_SHA384", task_clock_unit="msec", competitors=None, with_base=True):
    """Writes the files a run of bench/run.sh leaves, with the change costing `change_factor` times
    the base on each input in `changed_inputs`: in the server's user and kernel instructions both,
    or with `kernel_only` in the kernel's alone, as a change that adds system calls costs. The base
    runs TLS_AES_256_GCM_SHA384 on its TLS input, and the change runs `change_cipher`. The server
    runs TEST_NANOSECONDS_PER_UNIT a unit, which perf writes in `task_clock_unit`. Each competitor
    in `competitors` costs its factor times the base, and with `with_base` false no base runs."""
    factors = dict(competitors or {})
    if with_base:
        factors["base"] = 1.0
    with open(os.path.join(directory, "machine.txt"), "w") as machine:
        machine.write(f"mode={mode}\nrounds={len(TEST_ROUND_FACTORS) - 1}\n")
    records = []
    for round_number, round_factor in enumerate(TEST_ROUND_FACTORS):
        for input_name, units in TEST_UNITS.items():
            for variant in ["change"] + sorted(factors):
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
                per_run = units if input_name.endswith("-many") else 16
                cipher = change_cipher if variant == "change" else "TLS_AES_256_GCM_SHA384"
                with open(name + ".h2load", "w") as h2load:
                    for run in range(units // per_run):
                        if "-tls-" in input_name:
                            h2load.write(TEST_TLS.format(cipher=cipher))
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

    def test_a_filter_run_compares_cpu_time(self):
        status, output = self.report(1.10, mode="filter")
        self.assertNotEqual(status, 0, output)
        self.assertIn("by cpu_nanoseconds per unit", output)
        self.assertIn("| h2-many | 1.1000 | 5.00% | loses |", output)


if __name__ == "__main__":
    if sys.argv[1:] == ["--test"]:
        unittest.main(argv=sys.argv[:1])
    main()
