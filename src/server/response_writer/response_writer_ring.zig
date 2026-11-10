//! The ring of a `ResponseWriter`'s body (decisions 103 and 127 as amended on 2026-11-09, design
//! §8 step 46). The body's writer writes into the entry's memory after the headers, and writes
//! again into memory whose bytes the engine released. The engine releases bytes at once over h11
//! and h2, which copy them inside `write_body`, and for a coded h3 response, whose encoder copies
//! them. It releases the bytes of an uncoded h3 response once the peer acknowledged them (RFC 9000
//! §3.1). Each function here is the slow path of a write that found no room, or of a cut that
//! found a run in every slot. The root exports none of it.
//!
//! A cut that finds no free slot adds its bytes to the newest run (the owner's ruling of
//! 2026-11-09). Three rules keep that safe:
//!
//! - The engine has not taken the newest run whole. So it reads none of the bytes added, and a
//!   run it took never changes. Over h3, QUIC may read such a run again after a loss.
//! - The newest run is in the memory, and it ends where the writer's bytes start. So the run
//!   stays one piece of the memory, in the order the program wrote it. `select` keeps this true:
//!   the writer's region leaves the newest run only when a slot is free.
//! - The bytes added are the writer's own, in a region that no run the engine holds overlaps.
const std = @import("std");
const assert = std.debug.assert;
const ResponseWriter = @import("response_writer.zig").ResponseWriter;

/// Takes back the runs at the front that the engine released. The octets the engine took, less
/// the octets it still reads, cover each run that goes, whole.
pub fn reclaim(response: *ResponseWriter) void {
    const held: u64 = response.sink.held_len(response.sink.context, response.id);
    assert(held <= response.taken_len - response.released_len);
    const released = response.taken_len - held;
    // Bounded by the runs the engine took.
    while (response.piece_released < response.piece_sent) {
        const len = response.pieces[response.piece_released].len;
        if (response.released_len + len > released) break;
        response.released_len += len;
        response.piece_released += 1;
    }
    assert(response.released_len <= released);
}

/// Frees the slots of the runs the engine released, and moves the other runs to the front.
pub fn free_pieces(response: *ResponseWriter) void {
    reclaim(response);
    const released = response.piece_released;
    if (released == 0) return;
    const rest = response.piece_count - released;
    std.mem.copyForwards([]const u8, response.pieces[0..rest], response.pieces[released..response.piece_count]);
    response.piece_count = rest;
    response.piece_sent -= released;
    response.piece_released = 0;
}

/// Gives the body's writer a free region of `need` octets at least, from memory whose bytes the
/// engine released, and returns whether it found one. Memory the engine may still read is never
/// written again (decision 103). The writer holds no bytes it has not cut into a run.
pub fn refill(response: *ResponseWriter, need: usize) bool {
    assert(response.writer.end == 0 and need > 0);
    // Before the body starts, after it ends, and once a wrapped response's trailers wait at the end
    // of its region, the region stays where it is.
    if (!response.body_started or response.ended or response.end_asked == .trailers) return false;
    reclaim(response);
    if (select(response, need)) return true;
    wait_for_release(response);
    return false;
}

/// Asks the engine for a `writable` once it releases bytes, when the engine took every run and
/// still holds some. A run that waits for the engine already brings a `writable`.
pub fn wait_for_release(response: *ResponseWriter) void {
    const engine_waits = response.piece_sent < response.piece_count or (response.ended and !response.complete);
    if (engine_waits or response.piece_released == response.piece_count) return;
    response.sink.wait_release(response.sink.context, response.id);
    response.release_waited = true;
}

/// The slow path of a cut that found a run in every slot (the owner's ruling of 2026-11-09). It
/// frees the slots of the runs the engine released, and cuts a run of the writer's bytes. With no
/// slot free, it adds them to the newest run. When that run cannot take them, they stay in the
/// writer, the next `writable` cuts again, and the call returns `error.Full`.
pub fn cut_full(response: *ResponseWriter) error{Full}!void {
    const written = response.writer.end;
    assert(written > 0 and response.piece_count == response.pieces.len);
    free_pieces(response);
    if (response.piece_count < response.pieces.len) {
        response.pieces[response.piece_count] = response.writer.buffer[0..written];
        response.piece_count += 1;
    } else if (!extend_newest(response, written)) {
        response.cut_owed = true;
        wait_for_release(response);
        return error.Full;
    }
    response.cut_owed = false;
    response.writer.buffer = response.writer.buffer[written..];
    response.writer.end = 0;
}

/// Adds the `written` octets at the front of the writer's region to the newest run, and returns
/// whether it did. A run the engine took whole stays as it is, since the engine may read it in
/// place (decision 103). So does a run of `write_kept`, whose octets are the program's.
fn extend_newest(response: *ResponseWriter, written: usize) bool {
    if (response.piece_sent == response.piece_count) return false;
    const newest = &response.pieces[response.piece_count - 1];
    if (!in_memory(response, newest.*)) return false;
    const at = offset_of(response, response.writer.buffer.ptr);
    // `select` moved the region from the newest run only with a slot free, so the run ends where
    // the writer's octets start, and no run the engine holds lies under them.
    assert(offset_of(response, newest.ptr) + newest.len == at);
    assert(!overlaps_held(response, at, at + written));
    newest.len += written;
    return true;
}

/// Places the writer over a free region of `need` octets at least: after the newest run, or from
/// the region's start up to the oldest run the engine holds. Returns false when neither has room.
fn select(response: *ResponseWriter, need: usize) bool {
    const low = response.header_len;
    const high = response.memory.len;
    const at = offset_of(response, response.writer.buffer.ptr);
    const oldest = oldest_held(response) orelse return place(response, low, high, need);
    if (oldest < at) {
        if (high - at >= need) return place(response, at, high, need);
        // The region leaves the newest run only when a slot is free for the run cut next. So a
        // cut that finds no slot finds the newest run before its bytes, and adds them to it.
        if (response.piece_count - response.piece_released == response.pieces.len) return false;
        return place(response, low, oldest, need);
    }
    return place(response, at, oldest, need);
}

fn place(response: *ResponseWriter, from: usize, to: usize, need: usize) bool {
    assert(from <= to and to <= response.memory.len);
    if (to - from < need) return false;
    assert(!overlaps_held(response, from, to));
    response.writer.buffer = response.memory[from..to];
    response.writer.end = 0;
    return true;
}

/// The offset in the memory of the oldest run the engine holds there, or null when it holds none.
fn oldest_held(response: *const ResponseWriter) ?usize {
    for (response.pieces[response.piece_released..response.piece_count]) |piece| {
        if (in_memory(response, piece)) return offset_of(response, piece.ptr);
    }
    return null;
}

/// Whether a run the engine holds lies in the memory from `from` to `to`.
pub fn overlaps_held(response: *const ResponseWriter, from: usize, to: usize) bool {
    for (response.pieces[response.piece_released..response.piece_count]) |piece| {
        if (!in_memory(response, piece)) continue;
        const start = offset_of(response, piece.ptr);
        if (start < to and from < start + piece.len) return true;
    }
    return false;
}

/// Whether `piece` is in the entry's memory, and not bytes the program keeps (`write_kept`).
fn in_memory(response: *const ResponseWriter, piece: []const u8) bool {
    const start = @intFromPtr(response.memory.ptr);
    const at = @intFromPtr(piece.ptr);
    return at >= start and at < start + response.memory.len;
}

fn offset_of(response: *const ResponseWriter, pointer: [*]const u8) usize {
    const at = @intFromPtr(pointer) - @intFromPtr(response.memory.ptr);
    assert(at <= response.memory.len);
    return at;
}
