//! The errors of `.private`, in colibri's own members (decision 159, the owner's answer 7). The
//! Rotor host returns these sets, and each of Rotor's errors coerces into one of them. So a change
//! of a name in Rotor fails to compile in the host, and breaks no dependent.
const server = @import("server");

/// A bind of the listener or an open of a UDP socket failed.
pub const BindError = error{
    /// `host` is not an IPv4 or IPv6 literal.
    HostInvalid,
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

/// A run failed: its loop could not start or wait, the system refused the receive buffers, or the
/// engine could not start.
pub const RunError = server.StartError || error{
    Unsupported,
    PermissionDenied,
    SystemResources,
    Unexpected,
};
