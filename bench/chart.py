"""The charts of the README's Performance section, drawn from the reports of bench/run.sh.

`cpu` reads the report of `bench/run.sh --competitors --h11 --h3`. For each load of many requests
it draws the CPU time a request of each server: the time the server's threads ran, in user space
and in the kernel, over the requests the load sent. Shorter is better.

`throughput` reads the report of `bench/run.sh --throughput`: for each load of many requests, the
requests a second each server reached under h2load or wrk at full speed, and a bar marked ≥ where
the server's core was not full, so the load tool was the limit. Longer is better.

`latency` reads the report of `bench/run.sh --latency`, and draws each server's p99 at each rate
oha offered. A filled point is a rate the server sustained: every request answered 200, 95% of
the rate reached in every round, and p99 under the bound. A hollow point is a rate it did not
sustain.

Each bar chart gives every other server's value as a multiple of colibri's, each panel on its own
scale. Its title says where colibri is best, where another server ties it, and where another
server is better. Two servers tie when their values differ by no more than the larger of their two
spreads, the noise bench/report.py judges a change by.

<run> is the number of the run of bench.yml that wrote the report. The subtitle names it with the
commit and the machine the report names, as docs/performance.md asks of a published number.

    python3 bench/chart.py cpu <report.md> <run> [out.svg]
    python3 bench/chart.py throughput <report.md> <run> [out.svg]
    python3 bench/chart.py latency <report.md> <run> [out.svg]
    python3 bench/chart.py --test
"""

import math
import pathlib
import re
import sys
import tempfile

# The loads of many requests the CPU chart draws, and each panel's title.
CPU_INPUTS = (
    ("h11-many", "h11"),
    ("h11-tls-many", "h11 over TLS"),
    ("h2-many", "h2"),
    ("h2-tls-many", "h2 over TLS"),
    ("h3-many", "h3"),
)
# The protocols of the latency report, and each panel's title.
LATENCY_PROTOCOLS = (("h11", "h11"), ("h2", "h2"), ("h2-tls", "h2 over TLS"), ("h3", "h3"))
# Each server's name in a report, and its name in a chart. The judge's report names colibri
# `change`.
NAMES = {"change": "colibri", "httpz": "http.zig", "fastify": "Fastify", "nethttp": "net/http",
         "chi": "net/http + chi"}
# The CPU parts the latency report names by their MIDR part number.
CPU_PARTS = {"0xd49": "Neoverse-N2"}
# The share of a rate that oha must reach for the rate to count as sustained, as
# bench/report_latency.py counts it.
REACHED_SHARE = 0.95
# The color of each server in the latency chart, one categorical slot each, in a fixed order:
# blue, orange, aqua, yellow and magenta. The bar charts draw colibri in blue and every other
# server in gray.
SLOTS = {"colibri": "--s1", "net/http + chi": "--s2", "axum": "--s3", "http.zig": "--s4", "Fastify": "--s5"}
NANOSECONDS_PER_MICROSECOND = 1000.0
# The longest title line the charts' width holds at the title's font.
TITLE_LEN_MAX = 88
WIDTH = 840
PAD = 24

STYLE = '''<style>
svg { --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e; --muted:#8a8984; --grid:#e4e3df; --other:#a3a29c;
  --s1:#2a78d6; --s2:#eb6834; --s3:#1baf7a; --s4:#eda100; --s5:#e87ba4; }
@media (prefers-color-scheme: dark) {
  svg { --surface:#1a1a19; --ink:#f0efec; --ink2:#c3c2b7; --muted:#8f8e86; --grid:#33332f; --other:#6b6a64;
    --s1:#3987e5; --s2:#d95926; --s3:#199e70; --s4:#c98500; --s5:#d55181; }
}
text { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: var(--ink); }
.title { font-size: 16px; font-weight: 600; }
.sub { font-size: 12.5px; fill: var(--ink2); }
.panel { font-size: 14px; font-weight: 600; }
.row { font-size: 12.5px; fill: var(--ink2); }
.val { font-size: 11px; font-weight: 600; }
.tick { font-size: 11px; fill: var(--muted); }
.legend { font-size: 12.5px; fill: var(--ink2); }
</style>'''


def number(text):
    """The first number of a cell such as `6,215.1 (3.38%)` or `2000.00 (1990.00–2010.00)`."""
    return float(text.split()[0].replace(",", ""))


def name_of(variant):
    return NAMES.get(variant, variant)


def cells_of(line):
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def joined(labels):
    return labels[0] if len(labels) == 1 else ", ".join(labels[:-1]) + " and " + labels[-1]


def svg_head(height, title, description):
    return [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height}" width="{WIDTH}" '
            f'height="{height}" role="img" aria-labelledby="t d">',
            f'<title id="t">{title}</title>', f'<desc id="d">{description}</desc>', STYLE,
            f'<rect width="{WIDTH}" height="{height}" rx="8" fill="var(--surface)"/>']


def heading(title, lines):
    """The title and the lines under it, and the height they take. A title longer than the chart's
    width holds at its font breaks after its first clause."""
    title_lines = [title]
    if len(title) > TITLE_LEN_MAX:
        cut = max(title.rfind(mark, 0, TITLE_LEN_MAX) for mark in (", and ", "; ", ", "))
        title_lines = [title[:cut + 1], title[cut + 2:]]
    parts, y = [], 34
    for line in title_lines:
        parts.append(f'<text class="title" x="{PAD}" y="{y}">{line}</text>')
        y += 22
    for line in lines:
        parts.append(f'<text class="sub" x="{PAD}" y="{y}">{line}</text>')
        y += 18
    return parts, y


def nice_step(high, ticks_max):
    """The smallest of 1, 2 and 5 times a power of ten that marks [0, high] with ticks_max ticks."""
    power = 10 ** math.floor(math.log10(high / ticks_max))
    for factor in (1, 2, 5, 10):
        if high / (factor * power) <= ticks_max:
            return factor * power
    return 10 * power


def bar(x, y, width, height, fill):
    """A bar anchored at x whose far end is rounded."""
    width = max(width, 1)
    radius = min(4, width / 2)
    return (f'<path d="M{x},{y} h{width - radius:.1f} a{radius},{radius} 0 0 1 {radius},{radius} '
            f'v{height - 2 * radius} a{radius},{radius} 0 0 1 {-radius},{radius} h{-(width - radius):.1f} z" '
            f'fill="var({fill})"/>')


def verdict_title(values, labels, lower_wins, what):
    """The panels where colibri is best, the ones where another server ties it, and the ones where
    another server is better. `values` maps each panel to {server: (value, spread)}."""
    best, tied, lost = [], [], []
    for key, label in labels:
        if key not in values:
            continue
        colibri, colibri_spread = values[key]["colibri"]
        sign = 1 if lower_wins else -1
        verdicts = []
        for server, (value, spread) in values[key].items():
            if server == "colibri":
                continue
            noise = max(spread, colibri_spread)
            # Positive: the other server is worse than colibri, past the noise.
            margin = sign * (value - colibri) / colibri
            verdicts.append("lost" if margin < -noise else ("tied" if margin <= noise else "best"))
        (lost if "lost" in verdicts else tied if "tied" in verdicts else best).append(label)
    if len(best) == len(values):
        return f"colibri {what} in each load"
    title = f"colibri {what} in {joined(best)}" if best else "colibri"
    if tied:
        title += f", and ties for it in {joined(tied)}" if best else f" ties for {what.split(' ', 1)[1]} in {joined(tied)}"
    if lost:
        title += f"; another server is better in {joined(lost)}"
    return title


def bars_chart(values, labels, lower_wins, title, lines, unit, axis, description, at_least=None):
    """Panels of bars, two to a row: one panel for each label, colibri first and in blue, the other
    servers in gray, best first, each with its value as a multiple of colibri's."""
    panels = [(key, label) for key, label in labels if key in values]
    head, top = heading(title, lines)
    columns, panel_w, gap_x = 2, 384, 24
    rows_y = [top + 16]
    for first in range(0, len(panels), columns):
        rows_max = max(len(values[key]) for key, _ in panels[first:first + columns])
        rows_y.append(rows_y[-1] + 30 + rows_max * 27 + 28)
    parts = svg_head(rows_y[-1], title, description) + head
    for index, (key, label) in enumerate(panels):
        left = PAD + (index % columns) * (panel_w + gap_x)
        marked = (at_least or {}).get(key, ())
        parts += bars_panel(values[key], label, left, rows_y[index // columns], panel_w, lower_wins, unit, axis, marked)
    parts.append('</svg>')
    return "\n".join(parts) + "\n"


def bars_panel(servers, label, left, y0, panel_w, lower_wins, unit, axis, at_least=()):
    bar_h, bar_gap, label_w = 18, 9, 104
    parts = [f'<text class="panel" x="{left}" y="{y0 + 14}">{label}</text>']
    bar_left = left + label_w
    # The room right of the longest bar holds its label.
    bar_room = panel_w - label_w - 120
    high = max(value for value, _ in servers.values())
    step = nice_step(high, 4)
    scale = bar_room / (math.ceil(high / step) * step)
    others = sorted((s for s in servers if s != "colibri"), key=lambda s: servers[s][0], reverse=not lower_wins)
    order = ["colibri"] + others
    rows_y = y0 + 28
    axis_y = rows_y + len(order) * (bar_h + bar_gap)
    tick = 0.0
    while tick <= high + step / 2:
        x = bar_left + tick * scale
        parts.append(f'<line x1="{x:.1f}" y1="{rows_y - 4}" x2="{x:.1f}" y2="{axis_y - bar_gap + 4}" '
                     'stroke="var(--grid)" stroke-width="1"/>')
        parts.append(f'<text class="tick" x="{x:.1f}" y="{axis_y + 10}" text-anchor="middle">{unit(tick, axis=True)}</text>')
        tick += step
    parts.append(f'<text class="tick" x="{left + panel_w - 4}" y="{axis_y + 10}" text-anchor="end">{axis}</text>')
    colibri = servers["colibri"][0]
    for row, server in enumerate(order):
        y = rows_y + row * (bar_h + bar_gap)
        value = servers[server][0]
        fill = "--s1" if server == "colibri" else "--other"
        parts.append(f'<text class="row" x="{bar_left - 8}" y="{y + bar_h / 2 + 4:.1f}" text-anchor="end">{server}</text>')
        parts.append(bar(bar_left, y, value * scale, bar_h, fill))
        # The other server's cost as a multiple of colibri's, or colibri's rate as a multiple of
        # the other server's, so that each reads as how far apart the two are.
        ratio = value / colibri if lower_wins else colibri / value
        digits = 1 if ratio >= 10 else 2
        multiple = f"{ratio:.{digits}f}× colibri" if lower_wins else f"colibri {ratio:.{digits}f}×"
        times = "" if server == "colibri" else f", {multiple}"
        parts.append(f'<text class="val" x="{bar_left + value * scale + 6:.1f}" y="{y + bar_h / 2 + 4:.1f}">'
                     f'{"≥ " if server in at_least else ""}{unit(value)}{times}</text>')
    return parts


def read_cpu(text):
    """{input: {server: (nanoseconds a request, spread)}}, and the machine and the commit."""
    values, header = {}, {}
    for line in text.splitlines():
        match = re.fullmatch(r"- ([\w ,]+): (.*)", line.strip())
        if match:
            header.setdefault(match.group(1), match.group(2))
        if not line.startswith("|"):
            continue
        cells = cells_of(line)
        # | input | request | variant | rounds | instructions | user | cycles | system calls | CPU |
        if len(cells) == 9 and cells[0] in dict(CPU_INPUTS):
            spread = float(re.search(r"\(([0-9.]+)%\)", cells[8]).group(1)) / 100
            values.setdefault(cells[0], {})[name_of(cells[2])] = (number(cells[8]), spread)
    machine = ", ".join(header[key] for key in ("cpu", "kernel") if key in header)
    return values, machine, header.get("change", "unknown")


def microseconds(nanoseconds, axis=False):
    return f"{nanoseconds / NANOSECONDS_PER_MICROSECOND:g}" if axis else f"{nanoseconds / NANOSECONDS_PER_MICROSECOND:.1f} µs"


def cpu_chart(text, run):
    values, machine, commit = read_cpu(text)
    require_colibri(values)
    title = verdict_title(values, CPU_INPUTS, True, "takes the least CPU time a request")
    lines = ["The time the server's threads ran, in user space and in the kernel, over the requests of the load. Shorter is better.",
             "Each server runs on a core of its own. From two other cores, wrk sends 16 connections, and h2load 16 of 10 streams each.",
             f"One run of bench.yml measured all: run {run}, commit {commit}, {machine}."]
    return bars_chart(values, CPU_INPUTS, True, title, lines, microseconds, "µs a request",
                      f"{title}. " + described(values, CPU_INPUTS, microseconds))


def require_colibri(values):
    if not values or any("colibri" not in servers or len(servers) < 2 for servers in values.values()):
        sys.exit("chart.py: the report holds no panel with colibri and another server")


def described(values, labels, unit):
    return "; ".join(f"{label}: " + ", ".join(f"{server} {unit(value)}" for server, (value, _) in values[key].items())
                     for key, label in labels if key in values) + "."


def read_latency(text):
    """The bound, the machine, the commit, and {protocol: {server: [point]}}, where each point is
    (rate, reached, reached spread, p99, every answer 200, sustained)."""
    match = re.search(r"median p99 stays under ([0-9.]+) ms", text)
    if not match:
        sys.exit("chart.py: the report names no bound on p99")
    bound = float(match.group(1))
    header = dict(re.findall(r"^(\w+)=(.*)$", text, re.M))
    machine = ", ".join(value for value in (CPU_PARTS.get(header.get("cpu"), header.get("cpu")), header.get("kernel")) if value)
    commit = header.get("colibri", "unknown").split(",")[0]
    runs, protocol = {}, None
    for line in text.splitlines():
        if line.startswith("## "):
            protocol = line[3:].strip()
            continue
        if not line.startswith("|") or protocol not in dict(LATENCY_PROTOCOLS):
            continue
        cells = cells_of(line)
        # | server | rate | reached | p50 | p99 | p99.9 | all 200 |
        if len(cells) != 7 or not cells[1].isdigit():
            continue
        rate, reached = int(cells[1]), number(cells[2])
        low, high = (float(value) for value in re.search(r"\(([0-9.]+)–([0-9.]+)\)", cells[2]).groups())
        p99, answered = number(cells[4]), cells[6] == "yes"
        held = answered and low >= REACHED_SHARE * rate and p99 <= bound
        point = (rate, reached, (high - low) / reached, p99, answered, held)
        runs.setdefault(protocol, {}).setdefault(name_of(cells[0]), []).append(point)
    return bound, machine, commit, runs


def requests_a_second(value, axis=False):
    if axis:
        if value >= 1_000_000:
            return f"{value / 1_000_000:g}M"
        return f"{value / 1000:g}k" if value else "0"
    return f"{value:,.0f} req/s"


def read_throughput(text):
    """{input: {server: (requests a second, spread)}}, the servers each load tool held back, and the
    machine and the commit, from a report of bench/run.sh --throughput."""
    header = dict(re.findall(r"^(\w+)=(.*)$", text, re.M))
    values, at_least, input_name = {}, {}, None
    for line in text.splitlines():
        if line.startswith("## "):
            input_name = line[3:].strip()
            continue
        if not line.startswith("|") or input_name not in dict(CPU_INPUTS):
            continue
        cells = cells_of(line)
        # | server | rounds | requests a second | busy | limit |
        if len(cells) != 5 or not cells[1].isdigit():
            continue
        server = name_of(cells[0])
        spread = float(re.search(r"\(([0-9.]+)%\)", cells[2]).group(1)) / 100
        values.setdefault(input_name, {})[server] = (number(cells[2]), spread)
        if cells[4] == "load":
            at_least.setdefault(input_name, set()).add(server)
    machine = ", ".join(value for value in (header.get("cpu"), header.get("kernel")) if value)
    return values, at_least, machine, header.get("change", "unknown")


def throughput_chart(text, run):
    values, at_least, machine, commit = read_throughput(text)
    require_colibri(values)
    title = verdict_title(values, CPU_INPUTS, False, "serves the most requests a second on one core")
    load = re.search(r"^throughput=(\d+) s a load, (\d+) connections, (\d+) streams", text, re.M)
    if not load:
        sys.exit("chart.py: the report names no load of --throughput")
    seconds, connections, streams = load.groups()
    lines = [f"h2load, or wrk for h11, loads each server at full speed for {seconds} s from two other cores, with {connections} connections",
             f"and {streams} streams on each h2 or h3 connection. Each server runs on a core of its own. Longer is better. A bar",
             "marked ≥ is a server whose core was not full, so the load tool was the limit.",
             f"One run of bench.yml measured all: run {run}, commit {commit}, {machine}."]
    return bars_chart(values, CPU_INPUTS, False, title, lines, requests_a_second, "requests a second",
                      f"{title}. " + described(values, CPU_INPUTS, requests_a_second), at_least)


def latency_chart(text, run):
    bound, machine, commit, runs = read_latency(text)
    require_colibri(runs)
    panels = [(key, label) for key, label in LATENCY_PROTOCOLS if key in runs]
    servers = [name for name in SLOTS if any(name in runs[key] for key, _ in panels)]
    title = f"p99 latency at each rate oha offers, with the bound of {bound:g} ms"
    head, top = heading(title, [
        "oha sends GET requests over the GitHub API's routes at fixed rates, with its latency correction. A filled point is a rate",
        f"the server sustained: every answer 200, 95% of the rate reached, and p99 under {bound:g} ms. chi is a router on Go's",
        f"net/http, and over h3 runs on quic-go, and axum on quinn. Each server runs on a core of its own. One run of bench.yml",
        f"measured all: run {run}, commit {commit}, {machine}."])
    plot_h, columns, panel_w, gap_x = 150, 2, 372, 48
    legend_y, top = top + 4, top + 40
    height = top + math.ceil(len(panels) / columns) * (plot_h + 72) + 8
    rates = sorted({point[0] for key, _ in panels for points in runs[key].values() for point in points})
    p99s = [point[3] for key, _ in panels for points in runs[key].values() for point in points]
    y_range = (10 ** math.floor(math.log10(min(p99s))), 10 ** math.ceil(math.log10(max(max(p99s), bound * 10))))
    description = "; ".join(f"{label}: " + ", ".join(
        f"{server} sustains " + sustained(runs[key][server]) for server in servers if server in runs[key])
        for key, label in panels)
    parts = svg_head(height, "The p99 latency of each server at fixed rates, colibri against other servers",
                     f"{title}. {description}.") + head
    legend_x = PAD
    for server in servers:
        parts.append(f'<rect x="{legend_x}" y="{legend_y}" width="12" height="12" rx="2" fill="var({SLOTS[server]})"/>')
        parts.append(f'<text class="legend" x="{legend_x + 18}" y="{legend_y + 10}">{server}</text>')
        legend_x += 18 + 7 * len(server) + 24
    for index, (key, label) in enumerate(panels):
        left = PAD + 40 + (index % columns) * (panel_w + gap_x)
        y0 = top + (index // columns) * (plot_h + 72)
        parts += latency_panel(runs[key], label, (left, y0, panel_w - 40, plot_h), rates, y_range, bound)
    parts.append('</svg>')
    return "\n".join(parts) + "\n"


def sustained(points):
    held = [point[0] for point in points if point[5]]
    return f"{max(held):,} req/s" if held else "no rate"


def latency_panel(servers, label, box, rates, y_range, bound):
    left, y0, plot_w, plot_h = box
    y_low, y_high = y_range
    top = y0 + 24

    def sx(rate):
        return left + (math.log10(rate) - math.log10(rates[0])) / (math.log10(rates[-1]) - math.log10(rates[0])) * plot_w

    def sy(ms):
        ms = min(max(ms, y_low), y_high)
        return top + plot_h - (math.log10(ms) - math.log10(y_low)) / (math.log10(y_high) - math.log10(y_low)) * plot_h

    parts = [f'<text class="panel" x="{left - 40}" y="{y0 + 10}">{label}</text>']
    for power in range(round(math.log10(y_low)), round(math.log10(y_high)) + 1):
        ms = 10.0 ** power
        y = sy(ms)
        is_bound = math.isclose(ms, bound)
        stroke = "var(--ink2)" if is_bound else "var(--grid)"
        dash = ' stroke-dasharray="4 3"' if is_bound else ""
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + plot_w}" y2="{y:.1f}" stroke="{stroke}" stroke-width="1"{dash}/>')
        parts.append(f'<text class="tick" x="{left - 6}" y="{y + 4:.1f}" text-anchor="end">{ms:g} ms</text>')
    for rate in rates:
        parts.append(f'<text class="tick" x="{sx(rate):.1f}" y="{top + plot_h + 16}" text-anchor="middle">{rate / 1000:g}k</text>')
    parts.append(f'<text class="tick" x="{left + plot_w}" y="{top + plot_h + 32}" text-anchor="end">requests a second offered</text>')
    for server in (name for name in reversed(list(SLOTS)) if name in servers):
        fill = SLOTS[server]
        points = [(sx(point[0]), sy(point[3]), point[5]) for point in sorted(servers[server])]
        parts.append(f'<polyline points="{" ".join(f"{x:.1f},{y:.1f}" for x, y, _ in points)}" fill="none" '
                     f'stroke="var({fill})" stroke-width="2"/>')
        for x, y, held in points:
            inside = f"var({fill})" if held else "var(--surface)"
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{inside}" stroke="var({fill})" stroke-width="2"/>')
    return parts


CPU_REPORT = """## bench/run.sh

- cpu: Neoverse-N2
- kernel: Linux 7.0
- change: 0123abcd

| Input | Unit | Variant | Rounds | Instructions | User | Cycles | System calls | CPU ns |
|---|---|---|---|---|---|---|---|---|
| h11-many | request | change | 5 | 1 | 1 | 1 | 1 | 6,000.0 (1.00%) |
| h11-many | request | httpz | 5 | 1 | 1 | 1 | 1 | 12,000.0 (1.00%) |
| h11-many | request | nginx | 5 | 1 | 1 | 1 | 1 | 9,000.0 (1.00%) |
| h2-many | request | change | 5 | 1 | 1 | 1 | 1 | 2,000.0 (1.00%) |
| h2-many | request | hyper | 5 | 1 | 1 | 1 | 1 | 1,000.0 (1.00%) |
| h2-one | connection | change | 5 | 1 | 1 | 1 | 1 | 99,000.0 (1.00%) |
| h2-routes-many | request | change | 5 | 1 | 1 | 1 | 1 | 3,000.0 (1.00%) |
| h3-many | quic-go | 0.1262 | 1.65% | wins |
"""

LATENCY_REPORT = """# Latency at fixed rates (design §8 step 13f)

```text
kernel=Linux 7.0
cpu=0xd49
colibri=0123abcd, zig 0.16.0
```

## Highest sustained rate

The highest rate whose median p99 stays under 10 ms, with every request answered 200 and 95% of the rate reached in every round.

## h2

| Server | Rate | Reached req/s | p50 | p99 | p99.9 | All 200 |
|---|---|---|---|---|---|---|
| chi | 1000 | 1000.00 (999.00–1000.00) | 0.20 (0.20–0.20) | 0.50 (0.50–0.50) | 1.00 (1.00–1.00) | yes |
| chi | 2000 | 1500.00 (1400.00–1600.00) | 0.20 (0.20–0.20) | 0.50 (0.50–0.50) | 1.00 (1.00–1.00) | yes |
| chi | 4000 | 4000.00 (3999.00–4000.00) | 0.20 (0.20–0.20) | 0.60 (0.60–0.60) | 1.00 (1.00–1.00) | no |
| colibri | 1000 | 1000.00 (999.00–1000.00) | 0.10 (0.10–0.10) | 0.30 (0.30–0.30) | 0.40 (0.40–0.40) | yes |
| colibri | 2000 | 2000.00 (1999.00–2000.00) | 0.10 (0.10–0.10) | 0.40 (0.40–0.40) | 0.50 (0.50–0.50) | yes |
| colibri | 4000 | 4000.00 (3999.00–4000.00) | 0.10 (0.10–0.10) | 20.00 (19.00–21.00) | 30.00 (30.00–30.00) | yes |

## h3

| Server | Rate | Reached req/s | p50 | p99 | p99.9 | All 200 |
|---|---|---|---|---|---|---|
| chi | 1000 | 1000.00 (900.00–1100.00) | 0.20 (0.20–0.20) | 0.50 (0.50–0.50) | 1.00 (1.00–1.00) | yes |
| colibri | 1000 | 1000.00 (990.00–1010.00) | 0.10 (0.10–0.10) | 0.30 (0.30–0.30) | 0.40 (0.40–0.40) | yes |
"""


THROUGHPUT_REPORT = """# Throughput at full load (design §8 step 13q)

```text
cpu=Neoverse-N2
kernel=Linux 7.0
change=0123abcd
throughput=10 s a load, 32 connections, 100 streams on each h2 or h3 connection, 2 load threads
```

## h2-many

| Server | Rounds | Requests a second | Busy | Limit |
|---|---|---|---|---|
| change | 3 | 400,000.0 (2.00%) | 0.62 | load |
| hyper | 3 | 190,000.0 (2.00%) | 0.99 | server |

## h11-many

| Server | Rounds | Requests a second | Busy | Limit |
|---|---|---|---|---|
| change | 3 | 150,000.0 (2.00%) | 0.97 | server |
| nginx | 3 | 149,000.0 (2.00%) | 0.98 | server |
"""


def test_cpu():
    cpu = cpu_chart(CPU_REPORT, "77")
    assert ">colibri takes the least CPU time a request in h11; another server is better in h2<" in cpu, cpu
    assert ">6.0 µs</text>" in cpu and "9.0 µs, 1.50× colibri<" in cpu and "12.0 µs, 2.00× colibri<" in cpu, cpu
    assert "1.0 µs, 0.50× colibri<" in cpu and "99.0" not in cpu, cpu
    assert "run 77, commit 0123abcd, Neoverse-N2, Linux 7.0." in cpu and ">http.zig<" in cpu, cpu
    # colibri's bar is first in its panel, and the other servers follow, the best first.
    h11 = cpu[cpu.index(">h11<"):cpu.index(">h2<")]
    assert h11.index(">colibri<") < h11.index(">nginx<") < h11.index(">http.zig<"), h11
    tied = CPU_REPORT.replace("9,000.0 (1.00%)", "6,100.0 (2.00%)")
    assert ">colibri ties for the least CPU time a request in h11; another server is better in h2<" in cpu_chart(tied, "77")


def test_latency():
    throughput = throughput_chart(THROUGHPUT_REPORT, "79")
    # colibri's core was not full, so its bar is a floor; hyper's was.
    assert ">colibri serves the most requests a second on one core in h2, and ties for it in h11<" in throughput, throughput
    assert ">≥ 400,000 req/s<" in throughput and ">190,000 req/s, colibri 2.11×<" in throughput, throughput
    assert ">nginx<" in throughput and "run 79, commit 0123abcd, Neoverse-N2, Linux 7.0." in throughput, throughput
    assert "for 10 s from two other cores, with 32 connections" in throughput and "and 100 streams" in throughput, throughput
    assert requests_a_second(1_000_000, True) == "1M" and requests_a_second(500_000, True) == "500k"
    latency = latency_chart(LATENCY_REPORT, "78")
    assert "h2: colibri sustains 2,000 req/s, net/http + chi sustains 1,000 req/s" in latency, latency
    # chi's 2,000 and 4,000 in h2, its 1,000 in h3, which reached 900 in a round, and colibri's 4,000,
    # whose p99 passed the bound.
    assert latency.count('fill="var(--surface)" stroke') == 4 and "net/http + chi sustains no rate" in latency, latency
    assert ">10 ms<" in latency and "stroke-dasharray" in latency and "commit 0123abcd," in latency, latency
    assert "Neoverse-N2, Linux 7.0." in latency, latency


def test():
    test_cpu()
    test_latency()
    with tempfile.TemporaryDirectory() as scratch:
        for kind, report in (("cpu", CPU_REPORT), ("throughput", THROUGHPUT_REPORT), ("latency", LATENCY_REPORT)):
            alone = "\n".join(line for line in report.splitlines() if "chi" not in line and "nginx" not in line
                              and "httpz" not in line and "hyper" not in line)
            path = pathlib.Path(scratch, f"{kind}.md")
            path.write_text(alone)
            try:
                main(["chart.py", kind, str(path), "1", str(pathlib.Path(scratch, "out.svg"))])
            except SystemExit as error:
                assert "colibri and another server" in str(error), error
            else:
                raise AssertionError(f"{kind}: a report with colibri alone drew a chart")
    print("chart.py: ok")


CHARTS = {"cpu": cpu_chart, "throughput": throughput_chart, "latency": latency_chart}


def main(argv):
    if argv[1:] == ["--test"]:
        test()
        return
    if len(argv) not in (4, 5) or argv[1] not in CHARTS:
        sys.exit(__doc__)
    kind, report, run = argv[1:4]
    out = argv[4] if len(argv) == 5 else f"docs/images/{kind}.svg"
    pathlib.Path(out).write_text(CHARTS[kind](pathlib.Path(report).read_text(), run))


if __name__ == "__main__":
    main(sys.argv)
