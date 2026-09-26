#!/usr/bin/env bash
#
# Every Zig snippet in README.md, docs/usage.md and examples/README.md is a verbatim excerpt of a
# file that runs: a program in examples/, which `zig build examples` runs, or tools/consumer/,
# which tools/consumer_check.sh builds and runs. A snippet found in neither is code no build
# checks, and this refuses it. Indentation is ignored, so an excerpt may come from inside a
# function.
#
#   tools/doc_snippets.sh
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "${repository_root}" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
documents = ["README.md", "docs/usage.md", "examples/README.md"]
sources = sorted(root.glob("examples/*.zig")) + [root / "tools/consumer/build.zig", root / "tools/consumer/main.zig"]
source_lines = {path: path.read_text().splitlines() for path in sources}


def dedent(lines):
    indents = [len(line) - len(line.lstrip(" ")) for line in lines if line.strip()]
    cut = min(indents) if indents else 0
    return [line[cut:] if line.strip() else "" for line in lines]


def source_of(block):
    for path, lines in source_lines.items():
        for start in range(len(lines) - len(block) + 1):
            if dedent(lines[start:start + len(block)]) == block:
                return path
    return None


failures = 0
for document in documents:
    text = (root / document).read_text()
    for match in re.finditer(r"^```zig\n(.*?)^```", text, re.S | re.M):
        block = dedent(match.group(1).rstrip("\n").split("\n"))
        line = text[:match.start()].count("\n") + 1
        source = source_of(block)
        if source is None:
            print(f"doc_snippets.sh: {document}:{line}: this Zig block is in no file that runs")
            failures += 1
        else:
            print(f"doc_snippets.sh: {document}:{line}: from {source.relative_to(root)}")
if failures:
    sys.exit(1)
print("doc_snippets.sh: every Zig block is an excerpt of code that runs")
PY
