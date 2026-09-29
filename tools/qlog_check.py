#!/usr/bin/env python3
"""Checks the qlog files colibri's UDP QUIC endpoint writes (design §8 step 18c, decision 102).

    tools/qlog_check.py <directory> [complete]

Every `.sqlog` file in the directory must be JSON Text Sequences (RFC 7464): each record an RS,
one JSON text (RFC 8259) and an LF. The first record is main schema §5's QlogFileSeq header, whose
group ID and vantage point are the ones the file's name gives (main schema §12.1). Every other
record is an event with the members main schema §7 requires, and the members quic-events §3
requires of its name, at a time no earlier than the record before it. colibri numbers each packet
number space's packets 0, 1, 2 and so on (RFC 9000 §12.3), so the packets a file logs as sent run
without a gap, and a gap is an event the log dropped.

With `complete`, each original destination connection ID must have a client file and a server
file, and each file must log its connection's close (quic-events §4.3). That is what a run of a
colibri client against a colibri server leaves when every connection ends, and a log cut short
leaves no close.
"""
import json
import os
import re
import sys

RECORD_SEPARATOR = "\x1e"
FILE_SCHEMA = "urn:ietf:params:qlog:file:sequential"
SERIALIZATION_FORMAT = "application/qlog+json-seq"
EVENT_SCHEMA = "urn:ietf:params:qlog:events:quic-13"
FILE_NAME = re.compile(r"^([0-9a-f]+)_(client|server)\.sqlog$")

# The packet number space of each packet type colibri sends (quic-events §8.6, §8.7).
SPACE_OF = {"initial": "initial", "handshake": "handshake", "1RTT": "application_data"}

# The members of `data` each event requires: the drafts' CDDL fields without a "?".
REQUIRED_DATA = {
    "quic:packet_sent": ("header",),
    "quic:packet_received": ("header",),
    "quic:connection_state_updated": ("new",),
    "quic:tuple_assigned": ("tuple_id",),
    "http3:stream_type_set": ("stream_id", "stream_type"),
    "http3:frame_created": ("stream_id", "frame"),
    "http3:frame_parsed": ("stream_id", "frame"),
}


def fail(path, message):
    sys.exit(f"qlog_check: {path}: {message}")


def records(path):
    """The JSON texts of the file, in order."""
    with open(path, encoding="ascii") as held:
        text = held.read()
    if not text.startswith(RECORD_SEPARATOR):
        fail(path, "the file does not start with a record separator")
    for index, record in enumerate(text.split(RECORD_SEPARATOR)[1:]):
        if not record.endswith("\n"):
            fail(path, f"record {index} does not end with a line feed")
        try:
            yield json.loads(record)
        except json.JSONDecodeError as error:
            fail(path, f"record {index} is not a JSON text: {error}")


def check_header(path, header, group_id, vantage_point):
    if header.get("file_schema") != FILE_SCHEMA:
        fail(path, "the header names another file schema")
    if header.get("serialization_format") != SERIALIZATION_FORMAT:
        fail(path, "the header names another serialization format")
    trace = header.get("trace", {})
    if EVENT_SCHEMA not in trace.get("event_schemas", []):
        fail(path, "the trace does not name the QUIC event schema")
    if trace.get("common_fields", {}).get("group_id") != group_id:
        fail(path, "the trace's group ID is not the one the file is named for")
    if trace.get("vantage_point", {}).get("type") != vantage_point:
        fail(path, "the trace's vantage point is not the one the file is named for")


def check_event(path, index, event, previous_time):
    for member in ("time", "name", "data"):
        if member not in event:
            fail(path, f"event {index} has no {member}")
    if event["time"] < previous_time:
        fail(path, f"event {index} is earlier than the one before it")
    for member in REQUIRED_DATA.get(event["name"], ()):
        if member not in event["data"]:
            fail(path, f"event {index}, {event['name']}, has no {member}")
    header = event["data"].get("header")
    if header is not None and "packet_type" not in header:
        fail(path, f"event {index}, {event['name']}, has a header with no packet_type")
    frame = event["data"].get("frame")
    if frame is not None and "frame_type" not in frame:
        fail(path, f"event {index}, {event['name']}, has a frame with no frame_type")
    return event["time"]


def check_numbers(path, events):
    """The packets sent in each space, numbered without a gap."""
    next_number = {}
    for event in events:
        if event["name"] != "quic:packet_sent":
            continue
        header = event["data"]["header"]
        space = SPACE_OF[header["packet_type"]]
        expected = next_number.get(space, 0)
        if header["packet_number"] != expected:
            fail(path, f"packet {expected} of the {space} space is missing")
        next_number[space] = expected + 1


def check_file(path, group_id, vantage_point, complete):
    """Checks one file and returns how many events it holds."""
    held = list(records(path))
    if not held:
        fail(path, "the file holds no record")
    check_header(path, held[0], group_id, vantage_point)
    previous_time = 0.0
    for index, event in enumerate(held[1:]):
        previous_time = check_event(path, index, event, previous_time)
    check_numbers(path, held[1:])
    if complete and not any(event["name"] == "quic:connection_closed" for event in held[1:]):
        fail(path, "the file does not log its connection's close")
    return len(held) - 1


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "complete"):
        sys.exit(__doc__)
    directory = sys.argv[1]
    complete = len(sys.argv) == 3
    names = sorted(name for name in os.listdir(directory) if name.endswith(".sqlog"))
    if not names:
        fail(directory, "no .sqlog file")
    vantage_points = {}
    events = 0
    for name in names:
        match = FILE_NAME.match(name)
        if match is None:
            fail(name, "the name is not <ODCID>_<vantage point>.sqlog")
        group_id, vantage_point = match.groups()
        events += check_file(os.path.join(directory, name), group_id, vantage_point, complete)
        vantage_points.setdefault(group_id, set()).add(vantage_point)
    if complete:
        for group_id, held in vantage_points.items():
            if held != {"client", "server"}:
                fail(directory, f"connection {group_id} has no {'client' if 'client' not in held else 'server'} file")
    print(f"qlog_check: {len(names)} files, {events} events, each record a JSON text")


if __name__ == "__main__":
    main()
