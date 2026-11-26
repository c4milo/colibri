"""What changed since the previous release, for the charts of bench/chart.py (design §8 step 13u).

A chart records each value it draws for colibri in a file of values beside its SVG,
`docs/images/<chart>.json`, which the commit that draws the charts keeps. A chart drawn with
`--previous <file>`, the same chart's file of the previous release, marks colibri's values:

- a dashed line across colibri's bar at the previous release's value;
- after the bar's label, ▲ and the change when the value is `threshold` or more better, and ▼
  when it is that much worse. The latency chart marks colibri's highest sustained rate after
  each panel's name, and draws no line.

Two values of runs on different CPU models do not compare, so a chart whose machine differs from
the previous one's marks nothing, and says so. connect-zig's charts mark their changes the same
way, with the same threshold and colors.
"""

import json
import pathlib

# The least change, as a share of the previous value, that a chart marks better or worse.
threshold = 0.05
# The digits of a share that a comparison with the threshold reads, so that 105 against 100,
# whose quotient a float holds as a hair over 5%, counts as 5% exactly.
share_digits = 9
# The version of the file of values: a reader refuses a file of another version.
format_version = 1
# The command-line options that name the previous release's file of values and this release.
previous_option = "--previous"
release_option = "--release"
# The style of the marks, which bench/chart.py adds to its style sheet.
STYLE = """.better { fill: #1a7f37; } .worse { fill: #cf222e; }
@media (prefers-color-scheme: dark) { .better { fill: #3fb950; } .worse { fill: #f85149; } }
.was { stroke: var(--ink2); stroke-width: 1.5; stroke-dasharray: 2 2; }"""
# The height a chart adds for its line that explains the marks.
NOTE_HEIGHT = 22


def moved(share):
    """Whether a change moved by the threshold or more."""
    return share is not None and round(abs(share), share_digits) >= threshold


def option_value(arguments, option):
    """The arguments without `<option> <value>`, and the value, or None when the option is absent."""
    if option not in arguments:
        return arguments, None
    index = arguments.index(option)
    if index + 1 >= len(arguments):
        raise SystemExit(f"chart.py: {option} names no value")
    return arguments[:index] + arguments[index + 2 :], arguments[index + 1]


def load(path):
    """A file of values, or None when it names no file or holds another version."""
    if path is None or not pathlib.Path(path).exists():
        return None
    values = json.loads(pathlib.Path(path).read_text())
    return values if values.get("version") == format_version else None


class Change:
    """The values a chart draws for colibri, and their changes since the previous release."""

    def __init__(self, previous=None):
        self.given = previous
        self.previous = None
        self.other_machine = False
        self.machine = None
        self.commit = None
        self.records = {}
        self.tag = None if previous is None else previous.get("release") or f"run {previous.get('run')}"

    def read(self, machine, commit):
        """Takes the machine and the commit of this chart's report, and keeps the previous
        release's values only when they ran on the same CPU model. The machine names the CPU model
        first and the kernel after a comma, and a new kernel on the runner does not stop a
        comparison."""
        self.machine, self.commit = machine.split(",")[0].strip(), commit
        same_machine = self.given is not None and self.given.get("machine") == self.machine
        self.previous = self.given if same_machine else None
        self.other_machine = self.given is not None and not same_machine

    def record(self, key, label, value, higher_is_better):
        """Keeps a value the chart draws, under a key that names it in every release's file."""
        self.records[key] = {"label": label, "value": value, "higher_is_better": higher_is_better}

    def was(self, key):
        """The previous release's value of `key`, or None."""
        if self.previous is None:
            return None
        record = self.previous["values"].get(key)
        return None if record is None else record["value"]

    def share(self, key):
        """How much better the value of `key` is than the previous release's, as a share of it:
        below zero when it is worse. None when there is nothing to compare."""
        was, record = self.was(key), self.records.get(key)
        if not was or record is None:
            return None
        change = record["value"] / was - 1
        return change if record["higher_is_better"] else -change

    def mark(self, key):
        """The text after a label: ▲ or ▼ and the change, or nothing."""
        change = self.share(key)
        if not moved(change):
            return ""
        kind, arrow = ("better", "▲") if change > 0 else ("worse", "▼")
        return f' <tspan class="{kind}">{arrow}{abs(change) * 100:.0f}%</tspan>'

    def line(self, key, x_of, top, height):
        """A dashed line across a bar at the previous release's value, where `x_of` places a value."""
        was = self.was(key)
        if was is None:
            return None
        x = x_of(was)
        return f'<line class="was" x1="{x:.1f}" y1="{top - 2:.1f}" x2="{x:.1f}" y2="{top + height + 2:.1f}"/>'

    def note(self, what, lines):
        """The line that explains the marks, or None when the chart draws none. `what` names the
        value a mark compares, such as `colibri's value`, and `lines` says whether the chart draws
        the previous release's values as dashed lines."""
        if self.previous is not None:
            dashed = f", and a dashed line {self.tag}'s value" if lines else ""
            return (f"▲ marks {what} {threshold * 100:.0f}% or more better than {self.tag}'s, ▼ one "
                    f"that much worse{dashed}.")
        if self.other_machine:
            return f"{self.tag} ran on another CPU model, so this chart marks no change since it."
        return None

    def note_height(self, what, lines):
        return NOTE_HEIGHT if self.note(what, lines) else 0

    def draw_note(self, parts, what, lines, x, height):
        """The line that explains the marks, at the foot of a chart whose height includes it."""
        note = self.note(what, lines)
        if note:
            parts.append(f'<text class="sub" x="{x}" y="{height - 12}">{note}</text>')

    def write(self, svg_path, chart_name, run, release):
        """Writes the values beside the chart's SVG, as `<chart>.json`."""
        values = {
            "version": format_version,
            "chart": chart_name,
            "machine": self.machine,
            "run": run,
            "commit": self.commit,
            "release": release,
            "values": self.records,
        }
        pathlib.Path(svg_path).with_suffix(".json").write_text(json.dumps(values, indent=1) + "\n")
