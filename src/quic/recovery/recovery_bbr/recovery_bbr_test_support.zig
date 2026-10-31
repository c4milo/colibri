//! The driver the tests of BBRv3's states share: it feeds `Bbr` the ACK frames of a path whose
//! round trip and rate the tests choose. Test-only.
const constants = @import("../../constants.zig");
const recovery_delivery = @import("../recovery_delivery.zig");
const recovery_bbr = @import("recovery_bbr.zig");

const Bbr = recovery_bbr.Bbr;
const Path = recovery_bbr.Path;
const Sample = recovery_delivery.Sample;

pub const test_start_ns: u64 = 1_000_000_000;
pub const test_round_trip_ns: u64 = 50_000_000;
pub const test_datagram_len: u64 = 1_200;
pub const test_initial_window_len: u64 = 12_000;
pub const test_rate: u64 = 4_000_000;
/// The BDP of `test_rate` over `test_round_trip_ns`: 200,000 octets.
pub const test_bdp_len: u64 = 200_000;
pub const test_waits: u64 = 7;
pub const test_send_quantum_len: u64 = 2_400;
/// Each ACK frame acknowledges 10 datagrams.
pub const test_acknowledged_len: u64 = 12_000;
/// Four BDPs in flight: a queue that keeps Drain from ending.
pub const test_queue_len: u64 = 800_000;
/// Startup's rates: two rounds that double, then four at `test_rate`, the last three of which
/// do not grow it by a quarter.
pub const test_startup_first_rate: u64 = 1_000_000;
pub const test_startup_second_rate: u64 = 2_000_000;
pub const test_startup_rates = [_]u64{ test_startup_first_rate, test_startup_second_rate, test_rate, test_rate, test_rate, test_rate };

/// Feeds BBR one ACK frame a round trip, each of which ends a round. Test-only.
pub const Driver = struct {
    state: Bbr,
    delivery: recovery_delivery.Delivery,
    delivered_len: u64,
    now_ns: u64,
    /// `C.is_cwnd_limited` for every ACK frame.
    window_limited: bool,

    pub fn init(driver: *Driver) void {
        driver.now_ns = test_start_ns;
        driver.delivered_len = 0;
        driver.window_limited = false;
        driver.delivery.init();
        driver.state.init(test_start_ns, test_initial_window_len, test_waits);
    }

    pub fn path(driver: *const Driver, in_flight_len: u64) Path {
        return .{
            .now_ns = driver.now_ns,
            .in_flight_len = in_flight_len,
            .delivered_len = driver.delivered_len,
            .window_limited = driver.window_limited,
            .in_recovery = false,
            .datagram_len = test_datagram_len,
            .initial_window_len = test_initial_window_len,
            .send_quantum_len = test_send_quantum_len,
        };
    }

    /// One ACK frame `elapsed_ns` after the last, for a packet sent when the last one came.
    pub fn ack(driver: *Driver, elapsed_ns: u64, rate: u64, in_flight_len: u64) void {
        driver.ack_sent_at(elapsed_ns, rate, in_flight_len, driver.delivered_len);
    }

    /// One ACK frame for a packet sent before the round in progress began, which ends no round.
    pub fn ack_within_round(driver: *Driver, elapsed_ns: u64, rate: u64, in_flight_len: u64) void {
        driver.ack_sent_at(elapsed_ns, rate, in_flight_len, 0);
    }

    fn ack_sent_at(driver: *Driver, elapsed_ns: u64, rate: u64, in_flight_len: u64, prior_delivered_len: u64) void {
        driver.now_ns += elapsed_ns;
        const acknowledged_len = test_acknowledged_len;
        const sample: Sample = .{
            .rate = rate,
            .delivered_len = acknowledged_len,
            .interval_ns = test_round_trip_ns,
            .application_limited = false,
            .prior_delivered_len = prior_delivered_len,
            .acknowledged_len = acknowledged_len,
            .rtt_ns = test_round_trip_ns,
            .tx_in_flight_len = in_flight_len,
            .lost_len = 0,
        };
        driver.delivered_len += acknowledged_len;
        driver.state.on_ack(sample, driver.path(in_flight_len), &driver.delivery);
    }

    /// Startup at `test_rate` until the pipe is full, with a queue that keeps Drain from ending.
    pub fn fill_pipe(driver: *Driver) void {
        for (test_startup_rates) |rate| driver.ack(test_round_trip_ns, rate, test_queue_len);
    }

    /// Startup, Drain and the first round of ProbeBW_DOWN.
    pub fn reach_probe_bw(driver: *Driver) void {
        driver.fill_pipe();
        driver.ack(test_round_trip_ns, test_rate, 0);
    }
};
