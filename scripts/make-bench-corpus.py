#!/usr/bin/env python3
"""Build a throughput corpus from fixtures/ (M1 acceptance criterion 5).

Usage: scripts/make-bench-corpus.py OUT_DIR [SIZE_MB]   (default 1024)

Writes SIZE_MB of text into OUT_DIR as files of ~16 MiB. Each file repeats
fixture contents mixed with filler prose, so findings stay rare (as on real
disks) and the prefilter sees realistic keyword density. File names cycle
through agent-file shapes (transcripts, markdown, JSON settings, history), so
path routing is exercised too. All values are the invented fixture values.
"""
import os
import sys

root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")
out_dir = sys.argv[1]
size_mb = int(sys.argv[2]) if len(sys.argv) > 2 else 1024
file_mb = 16

fixtures = []
for d, _, files in os.walk(root):
    for f in sorted(files):
        if f in ("expected.json", "generate.py", "README.md"):
            continue
        with open(os.path.join(d, f), "rb") as fh:
            fixtures.append(fh.read())

filler = (
    b"The build finished; 214 tests passed and the cache was warm. "
    b"Refactored the parser module, updated docs, and bumped the version.\n"
) * 40

shapes = [
    "projects/p{n}/session-{n}.jsonl",
    "notes/history-{n}.md",
    "cfg/{n}/settings.json",
    "logs/run-{n}.log",
    "home{n}/.bash_history",
]

os.makedirs(out_dir, exist_ok=True)
chunk = b"".join(fx + b"\n" + filler for fx in fixtures)
target = file_mb * 1024 * 1024
written = 0
n = 0
while written < size_mb * 1024 * 1024:
    rel = shapes[n % len(shapes)].format(n=n)
    path = os.path.join(out_dir, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    reps = target // len(chunk) + 1
    data = (chunk * reps)[:target]
    data = data[: data.rfind(b"\n") + 1]
    with open(path, "wb") as fh:
        fh.write(data)
    written += len(data)
    n += 1
print(f"wrote {written / 1e6:.0f} MB in {n} files to {out_dir}")
