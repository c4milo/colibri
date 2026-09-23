"""Starts the QUIC Interop Runner's run.py on Python 3.14.

The runner needs Python 3.10 or newer. pyshark, which it reads packet captures with, assumes two
things Python 3.14 removed: an event loop asyncio creates on demand in the main thread, and the
child watcher API it uses to work around an older asyncio's handling of subprocesses. This sets
the loop, and stands in for the watcher with one that does nothing, because Python 3.14's asyncio
watches child processes itself. tools/interop.sh runs this from the runner's directory, with the
runner's own arguments.
"""
import asyncio
import os
import runpy
import sys

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
sys.argv = ["run.py"] + sys.argv[1:]
runpy.run_path("run.py", run_name="__main__")
