# Decision 59: The connection drives RFC 9002's loss recovery

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-23.

The design said recovery was the caller's to drive, and nothing drove it. A `Connection` holds
a `Recovery`, but `send` recorded no packet in it, an ACK frame updated only the packet number
space, and nothing called the loss timeout. A caller could not have done it either: ACK frames
are read inside `connection_frames.process` and never reach the caller. And every piece that
acts on an acknowledged or lost packet lives in the connection: CRYPTO, stream bytes, the flow
control frames, HANDSHAKE_DONE and the connection ID frames.

So the connection runs RFC 9002 itself. `send` records each packet it builds (Appendix A.5) and
sends no more than the congestion window allows (§7). An ACK frame runs `OnAckReceived`
(Appendix A.7) where the frame is read. The loss timer runs `OnLossDetectionTimeout`
(Appendix A.9). Both hand the packets they acknowledge or declare lost to every piece through
one function. The caller still places the storage those packets are written into (decision
35) and still supplies every instant (non-negotiable 3); what it no longer does is order
RFC 9002's steps.

The alternative refused: the caller drives, with ACK frames returned in the frame report and
one colibri function to hand their packets to every piece. That keeps the design text as it
was, but it puts the order of RFC 9002's steps in every caller, where the simulator cannot
check it, and a caller that forgets one breaks recovery with nothing to say so.
