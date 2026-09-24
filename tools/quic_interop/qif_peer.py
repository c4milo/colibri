#!/usr/bin/env python3
"""ls-qpack, through pylsqpack, on either side of the QIF interop of design §8 step 11.

pylsqpack is the QPACK of aioquic, and wraps ls-qpack. The files are the "QPACK Offline Interop"
format's: blocks of a 64-bit stream ID, a 32-bit length and the octets, both in network byte order,
where stream 0 is the encoder stream.

    qif_peer.py encode <input.qif> <output> <capacity> <blocked-streams> [reorder]
    qif_peer.py decode <input> <output.qif> <capacity> <blocked-streams>
    qif_peer.py compare <input.qif> <decoded.qif>

`reorder` writes each section ahead of the encoder stream octets written with it, so a decoder
that may block must. `compare` requires the decoded file's sets, each under a `# stream <id>`
comment, to be the input's in stream order.
"""

import struct
import sys

import pylsqpack

HEADER = struct.Struct(">QI")
ENCODER_STREAM = 0


def read_sets(path):
    """The header sets of a QIF file, each with the stream its `# stream` comment names, if any."""
    sets, current, stream = [], [], None
    for raw in open(path, "rb").read().split(b"\n"):
        line = raw.rstrip(b"\r")
        if line.startswith(b"#"):
            words = line[1:].split()
            if len(words) == 2 and words[0] == b"stream":
                stream = int(words[1])
            continue
        if not line:
            if current:
                sets.append((stream, current))
                current, stream = [], None
            continue
        name, _, value = line.partition(b"\t")
        current.append((name, value))
    if current:
        sets.append((stream, current))
    return sets


def write_block(out, stream_id, data):
    out.write(HEADER.pack(stream_id, len(data)))
    out.write(data)


def encode(source, output, capacity, blocked, reorder):
    encoder = pylsqpack.Encoder()
    settings = encoder.apply_settings(capacity, blocked)
    with open(output, "wb") as out:
        if settings:
            write_block(out, ENCODER_STREAM, settings)
        for stream_id, (_, headers) in enumerate(read_sets(source), 1):
            instructions, section = encoder.encode(stream_id, headers)
            if reorder:
                write_block(out, stream_id, section)
            if instructions:
                write_block(out, ENCODER_STREAM, instructions)
            if not reorder:
                write_block(out, stream_id, section)


def decode(source, output, capacity, blocked):
    decoder = pylsqpack.Decoder(capacity, blocked)
    data = open(source, "rb").read()
    decoded, position = {}, 0
    while position < len(data):
        stream_id, length = HEADER.unpack_from(data, position)
        position += HEADER.size
        chunk = data[position : position + length]
        position += length
        if stream_id == ENCODER_STREAM:
            for unblocked in decoder.feed_encoder(chunk):
                decoded[unblocked] = decoder.resume_header(unblocked)[1]
            continue
        try:
            decoded[stream_id] = decoder.feed_header(stream_id, chunk)[1]
        except pylsqpack.StreamBlocked:
            pass
    with open(output, "wb") as out:
        for stream_id in sorted(decoded):
            out.write(b"# stream %d\n" % stream_id)
            for name, value in decoded[stream_id]:
                out.write(name + b"\t" + value + b"\n")
            out.write(b"\n")


def compare(source, decoded):
    expected = [headers for _, headers in read_sets(source)]
    got = {stream: headers for stream, headers in read_sets(decoded)}
    if sorted(got) != list(range(1, len(expected) + 1)):
        sys.exit(f"compare: {decoded} holds streams {sorted(got)[:5]}..., not 1 to {len(expected)}")
    for stream_id, headers in enumerate(expected, 1):
        if got[stream_id] != headers:
            sys.exit(f"compare: stream {stream_id} differs")


def main(arguments):
    command = arguments[0] if arguments else ""
    if command == "encode" and len(arguments) in (5, 6):
        reorder = len(arguments) == 6 and arguments[5] == "reorder"
        encode(arguments[1], arguments[2], int(arguments[3]), int(arguments[4]), reorder)
    elif command == "decode" and len(arguments) == 5:
        decode(arguments[1], arguments[2], int(arguments[3]), int(arguments[4]))
    elif command == "compare" and len(arguments) == 3:
        compare(arguments[1], arguments[2])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
