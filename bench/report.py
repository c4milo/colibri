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

# Decision 33: anything under about 5% is noise until the judge's own floor, measured and
# recorded in docs/performance.md, says otherwise. BENCH_FLOOR sets it for one run.
FLOOR_DEFAULT = 0.05
# The rounds before this one are the warm-up, which the report discards.
FIRST_COUNTED_ROUND = 1
# The events a judge run counts, by the names perf stat writes.
JUDGE_EVENTS = ("instructions:u", "instructions:k", "cycles:u", "cycles:k", "task-clock", "raw_syscalls:sys_enter")
# The lines h2load writes about a TLS connection, and the order the report names them in.
H2LOAD_TLS = re.compile(r"^(TLS Protocol|Cipher|Server Temp Key): (.+)$", re.M)
TLS_NAMES = ("TLS Protocol", "Cipher", "Server Temp Key")
H2LOAD_REQUESTS = re.compile(r"requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded, (\d+) failed, (\d+) errored, (\d+) timeout")


def read_counts(path):
    """The counts a perf stat -x, file holds, by event, or the nanoseconds a filter run wrote."""
    counts = {}
    for line in open(path):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.strip().split(",")
        value, event = fields[0], fields[2]
        if value.startswith("<"):
            sys.exit(f"report.py: {path}: perf did not count {event}: {value}")
        counts[event] = float(value)
    return counts


def read_requests(path):
    """The requests h2load's reports in `path` say succeeded, which fails on any that did not."""
    succeeded = 0
    runs = H2LOAD_REQUESTS.findall(open(path).read())
    if not runs:
        sys.exit(f"report.py: {path}: no h2load report")
    for total, _, _, ok, failed, errored, timeout in runs:
        if int(ok) != int(total) or int(failed) or int(errored) or int(timeout):
            sys.exit(f"report.py: {path}: h2load: {ok} of {total} succeeded")
        succeeded += int(ok)
    return succeeded


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
        # perf stat writes task-clock, the time the server's threads ran, in milliseconds.
        "cpu_nanoseconds": counts["task-clock"] * 1e6 / units,
    }


def summarize(values):
    median = statistics.median(values)
    spread = (max(values) - min(values)) / median if median else 0.0
    return median, spread


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
    floor = float(os.environ.get("BENCH_FLOOR", FLOOR_DEFAULT))

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
    variants = [v for v in ("base", "change") if any((v, i) in samples for i in inputs)]
    rows, verdicts = [], []
    for input_name in inputs:
        unit = "request" if input_name.endswith("-many") else "connection"
        summary = {}
        for variant in variants:
            runs = samples[(variant, input_name)]
            summary[variant] = {metric: summarize([run[metric] for run in runs]) for metric in runs[0]}
            cells = " | ".join(f"{summary[variant][m][0]:,.1f} ({summary[variant][m][1] * 100:.1f}%)" for m in summary[variant])
            rows.append(f"| {input_name} | {unit} | {variant} | {len(runs)} | {cells} |")
        if len(variants) == 2:
            (base, base_spread), (change, change_spread) = summary["base"][primary], summary["change"][primary]
            ratio = change / base
            noise = max(base_spread, change_spread, floor)
            verdict = "loses" if ratio > 1 + noise else "wins" if ratio < 1 - noise else "within the noise"
            verdicts.append((verdict, f"| {input_name} | {ratio:.4f} | {noise * 100:.1f}% | {verdict} |"))

    metrics = list(samples[(variants[0], inputs[0])][0])
    lines = ["## bench/run.sh", ""]
    lines += [f"- {key}: {value}" for key, value in machine.items()]
    lines += [f"- tls, {variant}: {'; '.join(sorted(tls[variant]))}" for variant in variants if variant in tls]
    lines += [f"- floor: {floor * 100:.1f}%", ""]
    if verdicts:
        lines += [f"The change against the base, by {primary} per unit; losses first:", "",
                  "| Input | Change / base | Noise | Verdict |", "| --- | ---: | ---: | --- |"]
        order = {"loses": 0, "within the noise": 1, "wins": 2}
        lines += [row for _, row in sorted(verdicts, key=lambda v: order[v[0]])] + [""]
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
# What h2load writes about a TLS connection, before its count of requests.
TEST_TLS = "TLS Protocol: TLSv1.3\nCipher: {cipher}\nServer Temp Key: X25519 253 bits\nApplication protocol: h2\n"
# Each round's factor on every count. Round 0 is the warm-up and costs half as much again, as a
# first round can, so that a report that counts it shows a spread past the floor.
TEST_ROUND_FACTORS = (1.5, 1.004, 0.997, 1.002, 0.999, 1.001)


def write_test_run(directory, change_factor, changed_inputs=tuple(TEST_UNITS), failed_request=False, mode="judge", kernel_only=False,
                   change_cipher="TLS_AES_256_GCM_SHA384"):
    """Writes the files a run of bench/run.sh leaves, with the change costing `change_factor` times
    the base on each input in `changed_inputs`: in the server's user and kernel instructions both,
    or with `kernel_only` in the kernel's alone, as a change that adds system calls costs. The base
    runs TLS_AES_256_GCM_SHA384 on its TLS input, and the change runs `change_cipher`."""
    with open(os.path.join(directory, "machine.txt"), "w") as machine:
        machine.write(f"mode={mode}\nrounds={len(TEST_ROUND_FACTORS) - 1}\n")
    records = []
    for round_number, round_factor in enumerate(TEST_ROUND_FACTORS):
        for input_name, units in TEST_UNITS.items():
            for variant in ("base", "change"):
                name = os.path.join(directory, f"{variant}-{input_name}-{round_number}")
                changed = variant == "change" and input_name in changed_inputs
                base_instructions = TEST_INSTRUCTIONS_PER_UNIT[input_name] * units * round_factor
                user = base_instructions * 0.7 * (change_factor if changed and not kernel_only else 1.0)
                kernel = base_instructions * 0.3 * (change_factor if changed else 1.0)
                instructions = user + kernel
                with open(name + ".perf", "w") as perf:
                    if mode == "filter":
                        perf.write(f"{instructions / 10:.0f},,cpu_nanoseconds\n")
                    else:
                        perf.write(f"# started on a test\n\n{user:.0f},,instructions:u,1,100.00,,\n")
                        perf.write(f"{kernel:.0f},,instructions:k,1,100.00,,\n")
                        perf.write(f"{instructions:.0f},,cycles:u,1,100.00,,\n{instructions / 4:.0f},,cycles:k,1,100.00,,\n")
                        perf.write(f"{instructions / 3e6:.3f},msec,task-clock,1,100.00,,\n")
                        perf.write(f"{units * 4},,raw_syscalls:sys_enter,1,100.00,,\n")
                failed = 1 if failed_request and changed and round_number == 3 else 0
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
    def report(self, change_factor, **options):
        """report.py's exit status and output on a run with the change costing `change_factor`."""
        with tempfile.TemporaryDirectory() as directory:
            write_test_run(directory, change_factor, **options)
            result = subprocess.run([sys.executable, os.path.abspath(__file__), directory, os.path.join(directory, "report.md"),
                                     "--many-requests", str(TEST_UNITS["h2-many"]), "--one-connections", str(TEST_UNITS["h2-tls-one"])],
                                    capture_output=True, text=True, env=dict(os.environ, BENCH_FLOOR=str(FLOOR_DEFAULT)))
            return result.returncode, result.stdout + result.stderr

    def test_a_tree_against_itself_is_within_the_noise(self):
        status, output = self.report(1.0)
        self.assertEqual(status, 0, output)
        self.assertIn("| h2-many | 1.0000 | 5.0% | within the noise |", output)

    def test_a_cost_past_the_floor_loses_and_fails_the_run(self):
        status, output = self.report(1.10)
        self.assertNotEqual(status, 0, output)
        self.assertIn("| h2-many | 1.1000 | 5.0% | loses |", output)

    def test_a_saving_past_the_floor_wins(self):
        status, output = self.report(0.90)
        self.assertEqual(status, 0, output)
        self.assertIn("| h2-tls-one | 0.9000 | 5.0% | wins |", output)

    def test_a_cost_inside_the_floor_is_within_the_noise(self):
        status, output = self.report(1.04)
        self.assertEqual(status, 0, output)
        self.assertIn("| h2-tls-one | 1.0400 | 5.0% | within the noise |", output)

    def test_a_cost_in_the_kernel_loses(self):
        status, output = self.report(1.5, kernel_only=True)
        self.assertNotEqual(status, 0, output)
        self.assertIn("| h2-many | 1.1500 | 5.0% | loses |", output)

    def test_a_loss_is_listed_first(self):
        status, output = self.report(1.10, changed_inputs=("h2-tls-one",))
        self.assertNotEqual(status, 0, output)
        self.assertIn("| --- | ---: | ---: | --- |\n| h2-tls-one | 1.1000 | 5.0% | loses |\n", output)

    def test_a_failed_request_refuses_the_run(self):
        status, output = self.report(1.0, failed_request=True)
        self.assertNotEqual(status, 0, output)
        self.assertIn("h2load: 19999 of 20000 succeeded", output)

    def test_a_report_names_the_cipher_suite_each_build_ran(self):
        status, output = self.report(1.0, change_cipher="TLS_CHACHA20_POLY1305_SHA256")
        self.assertEqual(status, 0, output)
        self.assertIn("- tls, base: TLSv1.3, TLS_AES_256_GCM_SHA384, X25519 253 bits\n", output)
        self.assertIn("- tls, change: TLSv1.3, TLS_CHACHA20_POLY1305_SHA256, X25519 253 bits\n", output)

    def test_a_filter_run_compares_cpu_time(self):
        status, output = self.report(1.10, mode="filter")
        self.assertNotEqual(status, 0, output)
        self.assertIn("by cpu_nanoseconds per unit", output)
        self.assertIn("| h2-many | 1.1000 | 5.0% | loses |", output)


if __name__ == "__main__":
    if sys.argv[1:] == ["--test"]:
        unittest.main(argv=sys.argv[:1])
    main()
