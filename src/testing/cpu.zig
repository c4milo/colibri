//! The probe of the CPU that colibri's TLS values take (decision 97 as amended on 2026-09-30):
//! stdx's `platform.Cpu`. Each program probes the CPU it runs on once, through stdx's `platform`
//! module, and passes the result to every configuration.
const platform = @import("platform");
const tls = @import("tls");

/// The one probe a program makes, the first time it is asked for.
var probed: ?tls.Cpu align(@alignOf(?tls.Cpu)) = null;

pub fn probe() tls.Cpu {
    const cpu = probed orelse platform.probe();
    probed = cpu;
    return cpu;
}
