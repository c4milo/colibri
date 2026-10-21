"""Starts the QUIC Interop Runner's run.py on Python 3.14 and 3.15.

The runner needs Python 3.10 or newer. pyshark, which it reads packet captures with, assumes two
things Python 3.14 removed: an event loop asyncio creates on demand in the main thread, and the
child watcher API it uses to work around an older asyncio's handling of subprocesses. This sets
the loop, and stands in for the watcher with one that does nothing, because Python 3.14's asyncio
watches child processes itself. tools/interop.sh runs this from the runner's directory, with the
runner's own arguments.

prettytable 3.18.0 declares its submodule a lazy import (`__lazy_modules__`), which Python 3.15
obeys. Its deprecated constants then return the lazy import object and not their value, and
`set_style` refuses that object as MARKDOWN. The runner reads two of the constants, MARKDOWN and
ALL, so this sets the two to the values the submodule holds.
"""
import asyncio
import importlib
import os
import runpy
import sys

import prettytable

# run.py imports its neighbours, which live in the runner's directory and not in this one's.
sys.path.insert(0, os.getcwd())
asyncio.set_event_loop(asyncio.new_event_loop())


class NoChildWatcher:
    """What pyshark attaches its loop to. Python 3.14's asyncio needs no watcher."""

    def attach_loop(self, loop):
        pass


if not hasattr(asyncio, "set_child_watcher"):
    asyncio.SafeChildWatcher = NoChildWatcher
    asyncio.set_child_watcher = lambda watcher: None
    asyncio.get_child_watcher = NoChildWatcher
# A prettytable older than 3.12 holds the constants under their own names and needs nothing.
table_module = importlib.import_module("prettytable.prettytable")
for name in ("MARKDOWN", "ALL"):
    if hasattr(table_module, f"_DEPRECATED_{name}"):
        setattr(prettytable, name, getattr(table_module, f"_DEPRECATED_{name}"))
sys.argv = ["run.py"] + sys.argv[1:]
runpy.run_path("run.py", run_name="__main__")
