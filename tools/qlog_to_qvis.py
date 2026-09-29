#!/usr/bin/env python3
"""Rewrites a qlog file colibri wrote into the qlog 0.3 form qvis reads (decision 102 as amended).

    tools/qlog_to_qvis.py <input.sqlog> [output.sqlog]

colibri writes the drafts decision 102 pins: draft-ietf-quic-qlog-main-schema-14,
draft-ietf-quic-qlog-quic-events-13 and draft-ietf-quic-qlog-h3-events-13. qvis
(https://qvis.quictools.info) reads qlog 0.3, which draft-ietf-quic-qlog-main-schema-02,
draft-ietf-quic-qlog-quic-events-02 and draft-ietf-quic-qlog-h3-events-02 define. This rewrites
the header (main schema -02 §6.2), the event names, which carry the categories of -02, and the
members that changed between the two, and passes every other member through. Without an output
path it writes <input>.qvis.sqlog beside the input.
"""
import json
import os
import sys

RECORD_SEPARATOR = "\x1e"
HTTP3_EVENT_SCHEMA = "urn:ietf:params:qlog:events:http3-13"

# Quic-events -13 §3's names, and h3-events -13 §3's, to the category and name of -02.
EVENT_NAMES = {
    "quic:version_information": "transport:version_information",
    "quic:alpn_information": "transport:alpn_information",
    "quic:parameters_set": "transport:parameters_set",
    "quic:packet_sent": "transport:packet_sent",
    "quic:packet_received": "transport:packet_received",
    "quic:packet_dropped": "transport:packet_dropped",
    "quic:connection_state_updated": "connectivity:connection_state_updated",
    "quic:connection_closed": "connectivity:connection_closed",
    "quic:recovery_metrics_updated": "recovery:metrics_updated",
    "quic:packet_lost": "recovery:packet_lost",
    "http3:parameters_set": "http:parameters_set",
    "http3:stream_type_set": "http:stream_type_set",
    "http3:frame_created": "http:frame_created",
    "http3:frame_parsed": "http:frame_parsed",
}

# Quic-events -13 §4.7's tuple_assigned, which -02 has no event for, so the rewrite leaves it out,
# as it leaves out each event's tuple (main schema -14 §7.2).
LEFT_OUT = {"quic:tuple_assigned"}

# Quic-events -13 §5.7's reasons a packet was dropped, to the nearest of -02 §3.3.7. The others
# have none.
DROP_TRIGGERS = {
    "invalid": "header_parse_error",
    "connection_unknown": "unknown_connection_id",
    "decryption_failure": "payload_decrypt_error",
    "key_unavailable": "key_unavailable",
    "duplicate": "duplicate",
    "unsupported": "unsupported_version",
    "rejected": "dos_prevention",
}

# Quic-events -13 §4.3's triggers of a close, those -02 §3.1.3 names too.
CLOSE_TRIGGERS = {"idle_timeout", "application", "error", "version_mismatch", "stateless_reset"}

# H3-events -13 §3.3's stream types, to -02 §3.1.3's, which calls a request stream "data" and
# has no "unknown".
STREAM_TYPES = {"request": "data", "unknown": "reserved"}


def text_of(hexstring):
    """A hexstring as the text it spells when every octet is printable ASCII, else unchanged."""
    octets = bytes.fromhex(hexstring)
    if all(0x20 <= octet <= 0x7E for octet in octets):
        return octets.decode("ascii")
    return hexstring


def rename(members, old, new):
    if old in members:
        members[new] = members.pop(old)


def raw_member(members, member):
    """Takes `member` out of a frame's `raw` object, and drops the object once it is empty."""
    raw = members.get("raw", {})
    value = raw.pop(member, None)
    if not raw:
        members.pop("raw", None)
    return value


def application_code(members):
    """-13 writes an error it has no name for as "unknown" and its code, and -02 the code alone."""
    name = members.pop("error", None)
    code = members.pop("error_code", None)
    return code if name in (None, "unknown") else name


def quic_frame(frame):
    """One frame of quic-events -13 §8.13 as -02 Appendix A.12 writes it."""
    frame_type = frame["frame_type"]
    if frame_type == "padding":
        frame["payload_length"] = raw_member(frame, "payload_length")
    elif frame_type in ("crypto", "stream"):
        frame["length"] = raw_member(frame, "length")
    elif frame_type == "new_token":
        frame["token"] = {"length": frame.get("token", {}).get("raw", {}).get("length", 0)}
    elif frame_type in ("reset_stream", "stop_sending"):
        frame["error_code"] = application_code(frame)
    elif frame_type == "connection_close":
        close_frame(frame)
    return frame


def close_frame(frame):
    name = frame.pop("error", None)
    code = frame.pop("error_code", None)
    frame["error_code"] = code if name in (None, "unknown") else name
    if code is not None:
        frame["raw_error_code"] = code
    if "reason_bytes" in frame:
        frame["reason"] = text_of(frame.pop("reason_bytes"))


def http_frame(event):
    """The frame of an h3-events -13 frame event as -02 Appendix A.3 writes it, its payload's
    length moved to the event as -02 §3.1.4 has it."""
    frame = event["frame"]
    length = raw_member(frame, "payload_length")
    if length is not None:
        event["length"] = length
    if frame["frame_type"] == "headers":
        frame["headers"] = [field_line(line) for line in frame.get("headers", [])]
    elif frame["frame_type"] == "settings":
        frame["settings"] = [setting(entry) for entry in frame.get("settings", [])]
    elif frame["frame_type"] == "unknown":
        rename(frame, "frame_type_bytes", "raw_frame_type")
    elif frame["frame_type"] == "reserved":
        frame.pop("frame_type_bytes", None)
        frame["length"] = event.get("length", 0)


def field_line(line):
    """-02's HTTPField is text alone, so octets -13 wrote as a hexstring become text too."""
    name = line["name"] if "name" in line else bytes.fromhex(line["name_bytes"]).decode("latin-1")
    value = line["value"] if "value" in line else bytes.fromhex(line.get("value_bytes", "")).decode("latin-1")
    return {"name": name, "value": value}


def setting(entry):
    if entry.get("name") == "unknown":
        return {"name": f"unknown_0x{entry['name_bytes']:x}", "value": entry["value"]}
    return {"name": entry["name"], "value": entry["value"]}


def convert_data(name, data):
    """The members of one event, from what -13 defines to what -02 does."""
    rename(data, "initiator", "owner")
    if name in ("quic:packet_sent", "quic:packet_received"):
        data["frames"] = [quic_frame(frame) for frame in data.get("frames", [])]
    elif name == "quic:packet_dropped":
        trigger = DROP_TRIGGERS.get(data.pop("trigger", None))
        if trigger is not None:
            data["trigger"] = trigger
    elif name == "quic:alpn_information":
        data["chosen_alpn"] = text_of(data["chosen_alpn"]["byte_value"])
    elif name == "quic:connection_closed":
        closed(data)
    elif name == "http3:parameters_set":
        rename(data, "max_field_section_size", "max_header_list_size")
    elif name == "http3:stream_type_set":
        stream_type = data.pop("stream_type")
        data["new"] = STREAM_TYPES.get(stream_type, stream_type)
    elif name in ("http3:frame_created", "http3:frame_parsed"):
        http_frame(data)
    return data


def closed(data):
    if "connection_error" in data:
        name = data.pop("connection_error")
        code = data.pop("error_code", None)
        data["connection_code"] = code if name == "unknown" else name
    if "application_error" in data:
        data.pop("application_error")
        data["application_code"] = data.pop("error_code", None)
    if data.get("trigger") not in CLOSE_TRIGGERS:
        data.pop("trigger", None)


def header(record, title):
    """-02 §6.2's QlogFileSeq header, from -14 §5's."""
    trace = record["trace"]
    common = trace.get("common_fields", {})
    protocols = ["QUIC", "HTTP3"] if HTTP3_EVENT_SCHEMA in trace.get("event_schemas", []) else ["QUIC"]
    return {
        "qlog_version": "0.3",
        "qlog_format": "JSON-SEQ",
        "title": title,
        "trace": {
            "common_fields": {
                "protocol_type": protocols,
                "group_id": common.get("group_id", ""),
                # -02 counts relative times from a reference in milliseconds. colibri's clock has
                # no epoch (main schema -14 §7.1), so the reference is 0.
                "time_format": "relative",
                "reference_time": 0,
            },
            "vantage_point": trace.get("vantage_point", {}),
        },
    }


def convert(text, title):
    records = [json.loads(record) for record in text.split(RECORD_SEPARATOR)[1:]]
    if not records or "file_schema" not in records[0]:
        sys.exit(f"qlog_to_qvis: {title} does not start with a qlog header of main schema -14")
    converted = [header(records[0], title)]
    for event in records[1:]:
        name = event["name"]
        if name in LEFT_OUT:
            continue
        converted.append({"time": event["time"], "name": EVENT_NAMES.get(name, name), "data": convert_data(name, event["data"])})
    return "".join(RECORD_SEPARATOR + json.dumps(record, separators=(",", ":")) + "\n" for record in converted)


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    source = sys.argv[1]
    base, _ = os.path.splitext(source)
    destination = sys.argv[2] if len(sys.argv) == 3 else base + ".qvis.sqlog"
    with open(source, encoding="ascii") as held:
        text = held.read()
    with open(destination, "w", encoding="utf-8") as held:
        held.write(convert(text, os.path.basename(source)))
    print(f"qlog_to_qvis: wrote {destination}")


if __name__ == "__main__":
    main()
