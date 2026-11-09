//! The errors of `.private`, in colibri's own members (decision 159, the owner's answer 7). The
//! Rotor host returns these sets, and each of Rotor's errors coerces into one of them. So a change
//! of a name in Rotor fails to compile in the host, and breaks no dependent. A client's sets hold
//! no error of the server (decision 158 ruling 6).
const client = @import("client");
const server = @import("server");

/// A bind of the listener or an open of a UDP socket failed: the system's refusals, and a
/// server's `host` that is no IP literal.
pub const BindError = DatagramBindError || error{
    /// `host` is not an IPv4 or IPv6 literal.
    HostInvalid,
};

/// An open of a UDP socket on every interface failed: a client's, which parses no text.
pub const DatagramBindError = error{
    /// The system carries no stack for the address's family.
    AddressFamilyUnsupported,
    /// The process or the system may open no more descriptors.
    DescriptorLimit,
    SystemResources,
    /// Another socket holds the address.
    AddressInUse,
    /// No interface of this host has the address.
    AddressNotAvailable,
    /// Only a privileged process may bind the port.
    AccessDenied,
    NotSocket,
    Unexpected,
};

/// The loop of a run could not start or wait, or the system refused its receive buffers.
pub const LoopError = error{
    Unsupported,
    PermissionDenied,
    SystemResources,
    Unexpected,
};

/// A server's run failed: its loop failed, or the engine could not start.
pub const RunError = server.StartError || LoopError;

/// A client's `init` failed: the pool refused its configuration, or the UDP socket did not open.
/// The destination is a list of addresses, so no text is parsed (design §8 step 44g).
pub const ClientInitError = client.StartError || DatagramBindError;
