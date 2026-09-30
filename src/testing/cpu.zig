//! The answer about the CPU that colibri's TLS values require (decision 97 as amended): whether it
//! has the AES instructions and the carry-less multiply. Each program asks the CPU it runs on once,
//! through stdx's `platform` module, and passes the answer to every configuration.
const platform = @import("platform");
const tls = @import("tls");

/// The one probe a program makes, the first time an answer is asked for.
var probed: ?platform.Cpu align(@alignOf(?platform.Cpu)) = null;

/// `present` only for a CPU the probe says has both instructions. `no` and `not_known` answer
/// `absent`, which runs ChaCha20 and no AES instruction.
pub fn aes_instructions() tls.AesInstructions {
    const cpu = probed orelse platform.probe();
    probed = cpu;
    return if (cpu.aes_clmul == .yes) .present else .absent;
}
