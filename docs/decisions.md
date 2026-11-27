# Design decisions

Every entry here is a trade we made on purpose: what it costs, and what it buys. Changing one means
re-arguing the trade, not just editing the code. The README states what colibri does; this file
states why colibri does nothing more.

Entries marked **owner** are waiting on a ruling and are not settled. Everything else is settled
and is re-argued, not edited. A later ruling changes a decision in one of three ways, and the
words below name which:

- **Amended**: a dated paragraph inside the decision, or a later decision that says it amends
  this one, changes part of the ruling. The rest stands.
- **Reversed**: a later decision rules the opposite, and the title says so.
- **Adopted**: the decision was taken during a build step, before the owner ruled on it. It
  stands until the owner overrules it.

Each decision is a file in [`decisions/`](decisions/), listed below. A link to
`decisions.md#decision-94` still lands on that decision's row.

## Scope and shape

| Decision | Title |
| --- | --- |
| <a id="decision-1"></a>[1](decisions/0001-one-library-for-h2-and-h3.md) | One library for h2 and h3, not two in one repository. |
| <a id="decision-2"></a>[2](decisions/0002-no-http11-reversed-by-decision-88.md) | No HTTP/1.1. Reversed by decision 88 on 2026-09-24: colibri builds h11. |
| <a id="decision-3"></a>[3](decisions/0003-quic-is-a-module-inside-colibri.md) | QUIC is a module inside colibri, not its own library. |
| <a id="decision-4"></a>[4](decisions/0004-client-and-server-both-from-the.md) | Client and server, both, from the first step. |
| <a id="decision-5"></a>[5](decisions/0005-quic-knows-nothing-about-http.md) | `quic` knows nothing about HTTP. |

## What the caller supplies

| Decision | Title |
| --- | --- |
| <a id="decision-6"></a>[6](decisions/0006-colibri-owns-no-io.md) | colibri owns no I/O. |
| <a id="decision-7"></a>[7](decisions/0007-time-is-a-value-the-caller.md) | Time is a value the caller passes, never a clock read. |
| <a id="decision-8"></a>[8](decisions/0008-the-tls-provider-is-a-caller.md) | The TLS provider is a caller-supplied vtable with no production implementation in this tree. |
| <a id="decision-9"></a>[9](decisions/0009-packet-protection-is-a-second-caller.md) | Packet protection is a *second* caller-supplied vtable, so the TLS provider never has to carry AES. |
| <a id="decision-10"></a>[10](decisions/0010-chapulin-provides-all-of-colibris-crypto.md) | chapulin provides all of colibri's crypto, through colibri's two vtables. |

## What is shared between h2 and h3

Entries 11 to 16 are the shared-surface question answered from the RFC text. Three of them
correct a premise: a piece that looked shared and is not, or looked unshared and is.

| Decision | Title |
| --- | --- |
| <a id="decision-11"></a>[11](decisions/0011-the-huffman-coder-and-the-prefixed.md) | The Huffman coder and the prefixed-integer codec are shared, and both are RFC 7541's. |
| <a id="decision-12"></a>[12](decisions/0012-the-static-tables-and-the-index.md) | The static tables and the index address space are not shared, and cannot be. |
| <a id="decision-13"></a>[13](decisions/0013-correction-to-a-premise-flow-control.md) | Correction to a premise: flow control is not shared. |
| <a id="decision-14"></a>[14](decisions/0014-the-stream-table-is-not-shared.md) | The stream *table* is not shared; a bounded slot pool is. |
| <a id="decision-15"></a>[15](decisions/0015-the-semantics-core-is-shared-the.md) | The semantics core is shared; the verdicts are not. |
| <a id="decision-16"></a>[16](decisions/0016-no-caching-and-the-conformance-bar.md) | No caching, and the conformance bar for RFC 9111 is zero. |

## What colibri does not build

Each of the eight is a no with a reason, and each records what saying no still costs on the wire,
because a refused feature still imposes obligations on the wire. A ninth, decision 118 on
middleware, was reversed by decision 127 and stays here as a record.

| Decision | Title |
| --- | --- |
| <a id="decision-17"></a>[17](decisions/0017-server-push-no.md) | Server push: no. |
| <a id="decision-18"></a>[18](decisions/0018-priorities-no-to-scheduling-yes-to.md) | Priorities: no to scheduling, yes to the mandatory parsing. |
| <a id="decision-19"></a>[19](decisions/0019-extended-connect-no.md) | Extended CONNECT: no. |
| <a id="decision-20"></a>[20](decisions/0020-0-rtt-no-in-both-protocols.md) | 0-RTT: no, in both protocols. |
| <a id="decision-21"></a>[21](decisions/0021-connection-migration-no-to-initiating-it.md) | Connection migration: no to initiating it and no to accepting it — and this is the smallest saving of the seven. |
| <a id="decision-22"></a>[22](decisions/0022-http-datagrams-no-at-the-quic.md) | HTTP datagrams: no, at the QUIC layer. |
| <a id="decision-23"></a>[23](decisions/0023-multipath-no-and-there-is-nothing.md) | Multipath: no, and there is nothing to decline. |
| <a id="decision-118"></a>[118](decisions/0118-middleware-no-reversed-by-decision-127.md) | Middleware: no. Reversed by decision 127. |
| <a id="decision-148"></a>[148](decisions/0148-prague-congestion-control-no.md) | Prague congestion control: no. |

## Correctness

| Decision | Title |
| --- | --- |
| <a id="decision-24"></a>[24](decisions/0024-reading-the-rfc-is-not-evidence.md) | Reading the RFC is not evidence. |
| <a id="decision-25"></a>[25](decisions/0025-published-vectors-before-invented-ones.md) | Published vectors before invented ones. |
| <a id="decision-26"></a>[26](decisions/0026-the-golden-corpus-is-exact-bytes.md) | The golden corpus is exact bytes with a manifest |
| <a id="decision-27"></a>[27](decisions/0027-conformance-suites-are-checks-and-their.md) | Conformance suites are checks, and their versions are pinned. |
| <a id="decision-28"></a>[28](decisions/0028-interop-against-real-stacks-both-directions.md) | Interop against real stacks, both directions, is the bar for h3. |
| <a id="decision-29"></a>[29](decisions/0029-fuzz-every-parser-and-every-check.md) | Fuzz every parser, and every check is seeded. |
| <a id="decision-30"></a>[30](decisions/0030-the-deterministic-simulator-is-the-check.md) | The deterministic simulator is the check that the others cannot be. |

## Performance

| Decision | Title |
| --- | --- |
| <a id="decision-31"></a>[31](decisions/0031-the-workload-colibri-intends-to-win.md) | The workload colibri intends to win is many short connections with small requests and high connection churn |
| <a id="decision-32"></a>[32](decisions/0032-real-numbers-come-from-linux-and.md) | Real numbers come from Linux, and the machine is written down beside them. |
| <a id="decision-33"></a>[33](decisions/0033-the-method-is-fixed-before-the.md) | The method is fixed before the first measurement, so the numbers cannot be shaped later. |
| <a id="decision-34"></a>[34](decisions/0034-the-regression-check-has-two-layers.md) | The regression check has two layers. |

## Memory

Entry 35 was ruled after entries 1 to 34 were numbered, so it takes the next number.

| Decision | Title |
| --- | --- |
| <a id="decision-35"></a>[35](decisions/0035-colibri-is-zero-heap.md) | colibri is zero heap. |

## Tooling

Entry 36 was ruled after entries 1 to 35 were numbered, so it takes the next number.

| Decision | Title |
| --- | --- |
| <a id="decision-36"></a>[36](decisions/0036-colibris-developer-tooling-comes-from-pepegrillo.md) | colibri's developer tooling comes from pepegrillo, a Zig package pinned by hash. |

## The simulator

| Decision | Title |
| --- | --- |
| <a id="decision-37"></a>[37](decisions/0037-the-checks-and-the-zig-build.md) | The checks and the `zig build sim` command line are a module of their own, `sim_run`, rooted at `src/sim/run.zig`. |
| <a id="decision-38"></a>[38](decisions/0038-published-vectors-are-vendored-as-the.md) | Published vectors are vendored as the files their authors published, and a tool reads them. |

## The h2 connection

| Decision | Title |
| --- | --- |
| <a id="decision-39"></a>[39](decisions/0039-the-connection-consumes-one-frame-per.md) | The connection consumes one frame per call and returns what it produced. |
| <a id="decision-40"></a>[40](decisions/0040-a-field-block-is-decoded-fragment.md) | A field block is decoded fragment by fragment, and the connection holds one partial representation, never a whole block. |
| <a id="decision-41"></a>[41](decisions/0041-h2specs-two-self-dependency-cases-are.md) | h2spec's two self-dependency cases are skipped, because RFC 9113 is the authority. |
| <a id="decision-42"></a>[42](decisions/0042-a-client-accepts-any-number-of.md) | A client accepts any number of interim responses, with no limit of colibri's own. |
| <a id="decision-43"></a>[43](decisions/0043-the-record-mode-vtable-carries-negotiatedparameters.md) | The record-mode vtable carries `negotiated_parameters`, an eleventh member. |
| <a id="decision-44"></a>[44](decisions/0044-the-provider-is-an-optional-field.md) | The provider is an optional field on `h2.Connection`. |
| <a id="decision-45"></a>[45](decisions/0045-colibri-admits-tls-13-alone-and.md) | colibri admits TLS 1.3 alone, and three cipher suites. |
| <a id="decision-46"></a>[46](decisions/0046-every-endpoint-in-srctesting-does-its.md) | Every endpoint in `src/testing/` does its I/O without blocking. |
| <a id="decision-47"></a>[47](decisions/0047-every-check-runs-on-each-push.md) | Every check runs on each push to main, and the run leaves a report. |
| <a id="decision-48"></a>[48](decisions/0048-the-suite-holds-every-key-and.md) | The suite holds every key and protects every packet, and colibri holds none. |
| <a id="decision-49"></a>[49](decisions/0049-colibri-auto-tunes-its-flow-control.md) | colibri auto-tunes its flow control receive window. |
| <a id="decision-50"></a>[50](decisions/0050-where-rfc-9002-disagrees-with-itself.md) | Where RFC 9002 disagrees with itself about the round trip variation, colibri follows Appendix A.7. |
| <a id="decision-51"></a>[51](decisions/0051-h2-and-h3-share-their-message.md) | h2 and h3 share their message validation through `http`, and each names its own errors. |
| <a id="decision-52"></a>[52](decisions/0052-io-stays-outside-colibri-and-the.md) | I/O stays outside colibri, and the test endpoints keep their own loops for now. |
| <a id="decision-53"></a>[53](decisions/0053-colibri-reads-rfc-9846-not-rfc.md) | colibri reads RFC 9846, not RFC 8446, and re-cited all 158 citations against the revision rather than renumbering them by hand. |
| <a id="decision-54"></a>[54](decisions/0054-the-four-choices-rfc-9000-and.md) | The four choices RFC 9000 and RFC 9001 leave to a sender, ruled together. |
| <a id="decision-55"></a>[55](decisions/0055-the-retry-token-is-the-callers.md) | The Retry token is the caller's to mint and to check, and the instant is a parameter. |
| <a id="decision-56"></a>[56](decisions/0056-one-stream-frame-per-packet-so.md) | One STREAM frame per packet, so a lost packet's stream bytes are one range. |
| <a id="decision-57"></a>[57](decisions/0057-the-caller-keeps-a-streams-unacknowledged.md) | The caller keeps a stream's unacknowledged bytes, and colibri reads them through a stream provider. |
| <a id="decision-58"></a>[58](decisions/0058-rotor-is-the-loop-of-srctesting.md) | Rotor is the loop of `src/testing/`'s UDP endpoints, a third test-only dependency. |
| <a id="decision-59"></a>[59](decisions/0059-the-connection-drives-rfc-9002s-loss.md) | The connection drives RFC 9002's loss recovery. |
| <a id="decision-60"></a>[60](decisions/0060-one-call-takes-a-received-datagram.md) | One call takes a received datagram. |
| <a id="decision-61"></a>[61](decisions/0061-colibri-reassembles-received-stream-bytes-into.md) | colibri reassembles received stream bytes into a pool the caller places. |
| <a id="decision-62"></a>[62](decisions/0062-colibri-marks-each-levels-keys-installed.md) | colibri marks each level's keys installed, reading them from the suite, before the next packet. |
| <a id="decision-63"></a>[63](decisions/0063-the-test-only-udp-endpoints-take.md) | The test-only UDP endpoints take the instant from Rotor's loop. |
| <a id="decision-64"></a>[64](decisions/0064-a-pto-at-the-initial-or.md) | A PTO at the Initial or Handshake level declares that level's packets in flight lost, so its probe carries their CRYPTO bytes. |
| <a id="decision-65"></a>[65](decisions/0065-a-server-whose-client-shows-it.md) | A server whose client shows it lacks the server's Initial CRYPTO bytes sends them again at once, at most twice per connection. |
| <a id="decision-66"></a>[66](decisions/0066-a-pto-at-the-application-level.md) | A PTO at the application level declares the oldest ack-eliciting packets in flight lost, as many as the probes it owes, so the probes carry what those packets held. |
| <a id="decision-67"></a>[67](decisions/0067-tla-specifications-checked-by-the-tlc.md) | TLA+ specifications, checked by the TLC model checker, check the designs colibri's protocol decisions rule. |
| <a id="decision-68"></a>[68](decisions/0068-a-caller-says-with-two-flags.md) | A caller says, with two flags, whether it reads received ECN codepoints and whether it sets them on what it sends. |
| <a id="decision-69"></a>[69](decisions/0069-an-endpoint-with-ecnmarks-tests-a.md) | An endpoint with `ecn_marks` tests a path with its first ten marked packets or three PTOs, whichever ends first, as RFC 9000 Appendix A.4 describes. |
| <a id="decision-70"></a>[70](decisions/0070-a-pto-also-probes-every-other.md) | A PTO also probes every other packet number space that has ack-eliciting packets in flight, one packet each, coalesced into the same datagram when it fits. |
| <a id="decision-71"></a>[71](decisions/0071-decision-65s-second-early-resend-waits.md) | Decision 65's second early resend waits until one PTO has passed since the first. |
| <a id="decision-72"></a>[72](decisions/0072-the-caller-names-the-peer-address.md) | The caller names the peer address each datagram came from, and colibri decides when the path moves. |
| <a id="decision-73"></a>[73](decisions/0073-an-endpoint-that-sends-only-ack.md) | An endpoint that sends only ACK frames adds a PING about once a round trip, as RFC 9000 §13.2.4 suggests. |
| <a id="decision-74"></a>[74](decisions/0074-the-qpack-decoder-hands-a-blocked.md) | The QPACK decoder hands a blocked field section back to the caller unread, and holds the decoder instructions it owes until the caller asks for them. |
| <a id="decision-75"></a>[75](decisions/0075-the-qpack-vectors-are-a-lazy.md) | The QPACK vectors are a lazy Zig package, fetched once and pinned by hash, and a tool decodes them in `zig build test`. |
| <a id="decision-76"></a>[76](decisions/0076-the-qpack-encoder-inserts-before-it.md) | The QPACK encoder inserts before it writes a section, and references only entries that are safe to reference. |
| <a id="decision-77"></a>[77](decisions/0077-lean-4-proves-the-pure-arithmetic.md) | Lean 4 proves the pure arithmetic under colibri's codecs, and vector files tie each proved definition to the Zig function it mirrors. |
| <a id="decision-78"></a>[78](decisions/0078-colibri-reports-how-far-a-streams.md) | colibri reports how far a stream's bytes are acknowledged from its start. |
| <a id="decision-79"></a>[79](decisions/0079-h3-keeps-the-bytes-of-its.md) | h3 keeps the bytes of its own three streams, and the caller keeps every request stream's. |
| <a id="decision-80"></a>[80](decisions/0080-an-application-may-copy-a-streams.md) | An application may copy a stream's received bytes without reading them, and take them later. |
| <a id="decision-81"></a>[81](decisions/0081-h3-lets-the-qpack-encoder-insert.md) | h3 lets the QPACK encoder insert only what the encoder stream's flow-control credit carries. |
| <a id="decision-82"></a>[82](decisions/0082-the-test-only-tls-server-drives.md) | The test-only TLS server drives chapulin's record-mode handshake. |
| <a id="decision-83"></a>[83](decisions/0083-the-h2-endpoints-run-on-rotor.md) | The h2 endpoints run on Rotor too. |
| <a id="decision-84"></a>[84](decisions/0084-after-the-tls-provider-fails-the.md) | After the TLS provider fails, the suite says where the CONNECTION_CLOSE can go. |
| <a id="decision-85"></a>[85](decisions/0085-the-quic-object-is-built-suiteaesgcm.md) | The QUIC object is built `SUITE=aesgcm`, and every chapulin endpoint checks the object against the headers before it starts. |
| <a id="decision-86"></a>[86](decisions/0086-colibri-exports-its-ten-library-modules.md) | colibri exports its ten library modules by name, so a project that depends on it builds against them. |
| <a id="decision-87"></a>[87](decisions/0087-the-simulators-h3-trace-run-logs.md) | The simulator's h3 trace run logs every variable of `spec/tla/h3_connection`, and TLC checks each seed's log is a behavior of the model. |
| <a id="decision-88"></a>[88](decisions/0088-colibri-builds-http11-as-h11-client.md) | colibri builds HTTP/1.1 as h11, client and server. |
| <a id="decision-89"></a>[89](decisions/0089-colibri-writes-its-own-decoder-for.md) | colibri writes its own decoder for the `gzip` and `deflate` codings, in `src/deflate/`. |
| <a id="decision-90"></a>[90](decisions/0090-the-compression-codecs-live-in-stdx.md) | The compression codecs live in stdx, a repository of their own, and colibri imports it. |
| <a id="decision-91"></a>[91](decisions/0091-how-h11-uses-stdxs-gzip-and.md) | How h11 uses stdx's gzip and deflate decoders. |
| <a id="decision-92"></a>[92](decisions/0092-how-an-h11-connection-runs.md) | How an h11 connection runs. |
| <a id="decision-93"></a>[93](decisions/0093-h2s-writerequest-takes-an-indexing-choice.md) | h2's `write_request` takes an indexing choice for each field line. |
| <a id="decision-94"></a>[94](decisions/0094-colibri-links-chapulin-as-its-tls.md) | colibri links chapulin as its TLS stack and its packet protection. |
| <a id="decision-95"></a>[95](decisions/0095-h11-counts-body-bytes-the-caller.md) | h11 counts body bytes the caller sends from its own buffer. |
| <a id="decision-96"></a>[96](decisions/0096-examples-holds-programs-a-dependent-writes.md) | `examples/` holds programs a dependent writes, run on Rotor's loop over an in-memory link. |
| <a id="decision-97"></a>[97](decisions/0097-the-librarys-tls-module-is-tls.md) | The library's TLS module is `tls`, and the vtable it fills is `tls_provider`. |
| <a id="decision-98"></a>[98](decisions/0098-h11-decodes-a-coded-body-into.md) | h11 decodes a coded body into a buffer the caller passes to `receive`. |
| <a id="decision-99"></a>[99](decisions/0099-colibris-runs-of-the-quic-interop.md) | colibri's runs of the QUIC Interop Runner count the client's connection attempts as handshakes. |
| <a id="decision-100"></a>[100](decisions/0100-a-version-choosing-http-client-and.md) | A version-choosing HTTP client and a server of the same shape, above h11, h2 and h3. |
| <a id="decision-101"></a>[101](decisions/0101-the-client-and-server-code-content.md) | The client and server code content with stdx's encoders and decoders. |
| <a id="decision-102"></a>[102](decisions/0102-colibri-writes-qlog-when-its-caller.md) | colibri writes qlog when its caller asks, from the pinned drafts. |
| <a id="decision-103"></a>[103](decisions/0103-the-server-over-quic-one-endpoint.md) | The server over QUIC: one endpoint owns the connections, and the caller keeps each response body until the server reports it done. |
| <a id="decision-104"></a>[104](decisions/0104-an-h2-connection-model-and-a.md) | An h2 connection model, and a trace check of colibri's h2 against it. |
| <a id="decision-105"></a>[105](decisions/0105-a-model-of-the-clients-exchanges.md) | A model of the client's exchanges, and a trace check of the client against it. |
| <a id="decision-106"></a>[106](decisions/0106-colibris-runs-of-the-quic-interop.md) | colibri's runs of the QUIC Interop Runner pass a rebinding test's new path once the client answers any PATH_CHALLENGE sent on it. |
| <a id="decision-107"></a>[107](decisions/0107-a-probe-above-the-initial-level.md) | A probe above the Initial level repeats the latest ACK frame. |
| <a id="decision-108"></a>[108](decisions/0108-quic-version-2-beside-version-1.md) | QUIC version 2 beside version 1: each packet names its version, and a client switches once. |
| <a id="decision-109"></a>[109](decisions/0109-what-h11-does-with-the-bytes.md) | What h11 does with the bytes after a CONNECT or an Upgrade request. |
| <a id="decision-110"></a>[110](decisions/0110-the-servers-defences-against-denial-of.md) | The server's defences against denial of service: Rapid Reset first, then deadlines. |
| <a id="decision-111"></a>[111](decisions/0111-a-server-switches-every-client-that.md) | A server switches every client that lists version 2, and a client resumes in its ticket's version. |
| <a id="decision-112"></a>[112](decisions/0112-the-quic-interop-runner-reports-quinns.md) | The QUIC Interop Runner reports quinn's client in the `v2` case without failing the run. |
| <a id="decision-113"></a>[113](decisions/0113-a-rststream-the-caller-asks-for.md) | A RST_STREAM the caller asks for is owed by the stream's record, not queued. |
| <a id="decision-114"></a>[114](decisions/0114-no-check-toolscish-runs-binds-a.md) | No check `tools/ci.sh` runs binds a fixed port: the kernel chooses each one. |
| <a id="decision-115"></a>[115](decisions/0115-a-types-public-functions-are-the.md) | A type's public functions are the calls a program makes, and a module's root exports the types a program names. |
| <a id="decision-116"></a>[116](decisions/0116-over-h3-the-server-owes-a.md) | Over h3 the server owes a 100 (Continue) on a request's head alone, and none to a request whose stream has ended. |
| <a id="decision-117"></a>[117](decisions/0117-a-program-names-no-http-version.md) | A program names no HTTP version outside `versions`, and one endpoint serves every connection. |
| <a id="decision-119"></a>[119](decisions/0119-how-one-endpoint-serves-tcp-and.md) | How one endpoint serves TCP and QUIC. |
| <a id="decision-120"></a>[120](decisions/0120-a-clients-channel-builds-its-tls.md) | A client's channel builds its TLS configurations, draws what a QUIC connection starts from, and carries every exchange a program makes. |
| <a id="decision-121"></a>[121](decisions/0121-the-roots-of-server-and-client.md) | The roots of `server` and `client` export what an endpoint and a channel take and return. |
| <a id="decision-122"></a>[122](decisions/0122-serverroutes-matches-a-method-and-a.md) | `server.routes` matches a method and a path through a table the program declares at compile time. |
| <a id="decision-123"></a>[123](decisions/0123-quic-skips-packet-numbers-in-its.md) | QUIC skips packet numbers in its 1-RTT space to catch an optimistic ACK. |
| <a id="decision-124"></a>[124](decisions/0124-what-client-gives-a-program-that.md) | What `client` gives a program that leaves the protocol modules. |
| <a id="decision-125"></a>[125](decisions/0125-clientpool-holds-several-tcp-connections-to.md) | `client.Pool` holds several TCP connections to one origin, counted at run time. |
| <a id="decision-126"></a>[126](decisions/0126-the-server-and-client-apis-name.md) | The `server` and `client` APIs name each HTTP concept once, in colibri's own model. |
| <a id="decision-127"></a>[127](decisions/0127-the-server-reads-a-requests-query.md) | The server reads a request's query, and a route table calls the program's functions, with middleware. |
| <a id="decision-128"></a>[128](decisions/0128-a-route-tables-walk-backs-up.md) | A route table's walk backs up for a method, as it backs up for a path. |
| <a id="decision-129"></a>[129](decisions/0129-a-route-names-its-parameters-and.md) | A route names its parameters, and two routes may name one position differently. |
| <a id="decision-130"></a>[130](decisions/0130-a-quic-connections-client-may-hold.md) | A QUIC connection's client may hold 100 requests open, and gets each stream back as it closes. |
| <a id="decision-131"></a>[131](decisions/0131-a-packet-carries-up-to-16.md) | A packet carries up to 16 STREAM frames, and a ring holds the ranges after its first. |
| <a id="decision-132"></a>[132](decisions/0132-h2-puts-a-responses-field-lines.md) | h2 puts a response's field lines into HPACK's dynamic table, and empties both tables after a block it abandoned. |
| <a id="decision-133"></a>[133](decisions/0133-the-congestion-controller-is-cubic-in.md) | The congestion controller is CUBIC (RFC 9438), in place of RFC 9002's NewReno. |
| <a id="decision-134"></a>[134](decisions/0134-colibri-may-read-the-bbr-draft.md) | colibri may read the BBR draft, and builds BBRv3 beside CUBIC once CUBIC has landed. |
| <a id="decision-135"></a>[135](decisions/0135-cubics-first-slow-start-is-hystart.md) | CUBIC's first slow start is HyStart++ (RFC 9406). |
| <a id="decision-136"></a>[136](decisions/0136-bbrv3-draws-its-probe-waits-from.md) | BBRv3 draws its probe waits from one value the caller draws, a connection takes its controller from one enum, and a bulk download measures it first. |
| <a id="decision-137"></a>[137](decisions/0137-each-library-module-groups-its-constants.md) | Each library module groups its constants by who sets them: the protocol, the limits, the policy, and each algorithm's parameters, one file each. |
| <a id="decision-138"></a>[138](decisions/0138-h2-writes-a-data-frames-header.md) | h2 writes a DATA frame's header for data the caller writes after it. |
| <a id="decision-139"></a>[139](decisions/0139-a-provider-seals-a-frames-header.md) | A provider seals a frame's header and its data from two slices. |
| <a id="decision-140"></a>[140](decisions/0140-a-handshakes-key-exchange-group-is.md) | A handshake's key-exchange group is reported beside its cipher suite. |
| <a id="decision-141"></a>[141](decisions/0141-tlspem-reads-the-pem-files-an.md) | `tls.pem` reads the PEM files an operator holds. |
| <a id="decision-142"></a>[142](decisions/0142-dnssecs-signature-checks-are-a-module.md) | DNSSEC's signature checks are a module of their own, `dnssec`, and not a part of `tls`. |
| <a id="decision-143"></a>[143](decisions/0143-bbrv3-is-the-default-congestion-controller.md) | BBRv3 is the default congestion controller of colibri's QUIC connections. |
| <a id="decision-144"></a>[144](decisions/0144-dfuzz-builds-the-unit-tests-with.md) | `-Dfuzz` builds the unit tests with Zig 0.16.0's test runner, one line fixed. |
| <a id="decision-145"></a>[145](decisions/0145-no-ruling.md) | No ruling. |
| <a id="decision-146"></a>[146](decisions/0146-an-h11-client-bounds-the-drop.md) | An h11 client bounds the drop of a response the caller no longer reads. |
| <a id="decision-147"></a>[147](decisions/0147-a-servers-identities-are-one-shape.md) | A server's identities are one shape for every signature algorithm, and ML-DSA-87 is one. |
| <a id="decision-149"></a>[149](decisions/0149-colibris-quic-connections-may-resume-congestion.md) | colibri's QUIC connections may resume congestion state, by RFC 9959's Careful Resume. |
| <a id="decision-150"></a>[150](decisions/0150-colibri-binds-reads-its-files-and.md) | `colibri` binds, reads its files and runs the loop, through a `std.Io` the program may pass. |
| <a id="decision-151"></a>[151](decisions/0151-server-encodes-and-decodes-json-through.md) | `server` encodes and decodes JSON through stdx's `json` module. |
| <a id="decision-152"></a>[152](decisions/0152-clientresponse-holds-its-headers-and-trailers.md) | `client.Response` holds its headers and trailers in a `Headers` and a `Trailers`. |
| <a id="decision-153"></a>[153](decisions/0153-a-client-that-runs-on-a.md) | A client that runs on a `std.Io`, with streamed bodies under it. |
| <a id="decision-154"></a>[154](decisions/0154-one-reading-of-quic-gos-congestion.md) | One reading of quic-go's congestion controller, to explain a gap the judge measured. |
| <a id="decision-155"></a>[155](decisions/0155-quic-finds-each-paths-datagram-size.md) | QUIC finds each path's datagram size by DPLPMTUD (RFC 9000 §14.3, RFC 8899). |
| <a id="decision-156"></a>[156](decisions/0156-colibriclient-and-colibriserver-run-on-a.md) | `colibri.Client` and `colibri.Server` run on a Rotor loop that the program may share. |
| <a id="decision-157"></a>[157](decisions/0157-a-servers-endpoint-finds-a-datagrams.md) | A server's endpoint finds a datagram's connection from its Destination Connection ID in one table entry. |
| <a id="decision-158"></a>[158](decisions/0158-colibris-public-api-follows-tigerstyle-first.md) | colibri's public API follows TigerStyle first, and Zig 0.16's std where TigerStyle says nothing. |
| <a id="decision-159"></a>[159](decisions/0159-colibriclient-and-colibriserver-take-a-host.md) | `colibri.Client` and `colibri.Server` take a host interface in colibri's own terms, and Rotor is one host. |
| <a id="decision-160"></a>[160](decisions/0160-the-h11-server-reads-the-rest.md) | The h11 server reads the rest of a body that its response did not wait for, or closes in stages. |
| <a id="decision-161"></a>[161](decisions/0161-colibris-servers-issue-session-tickets-and.md) | colibri's servers issue session tickets, and colibri.Client resumes with them. |
| <a id="decision-162"></a>[162](decisions/0162-colibri-exports-nothing-of-chapulin-and.md) | colibri exports nothing of chapulin, and its object file for TLS over TCP holds JWS and SCRAM. |
| <a id="decision-163"></a>[163](decisions/0163-the-routers-handlers-take-the-programs.md) | The router's handlers take the program's context, the request's context, a request and a response, and a handler's form says what it gets. |
| <a id="decision-164"></a>[164](decisions/0164-line-coverage-comes-from-pepegrillos-tool.md) | Line coverage comes from pepegrillo's tool under kcov, and the badge from a named CI run. |
| <a id="decision-165"></a>[165](decisions/0165-the-servers-receive-writes-its-result.md) | The server's `receive` writes its result through a pointer, and a `server.Router` takes `*const server.Event`, from v0.19.0. |
| <a id="decision-166"></a>[166](decisions/0166-a-program-sets-six-sizes-of.md) | A program sets six sizes of a TCP connection through `server.Capacity`, at compile time, from v0.19.0, as ruled first; amended the same day to sizes colibri sets itself. |
| <a id="decision-167"></a>[167](decisions/0167-a-tcp-connection-over-tls-takes.md) | A TCP connection over TLS takes its TLS session from a buffer the program passes in `server.Config.tls_buffer`, from v0.19.0. |
| <a id="decision-168"></a>[168](decisions/0168-a-server-keeps-the-1-rtt.md) | A server keeps the 1-RTT packets that arrive before its handshake completes, and opens them once it completes. |
| <a id="decision-169"></a>[169](decisions/0169-a-configuration-holds-the-programs-cpu.md) | A configuration holds the program's CPU features, and a codec pool holds none. |
| <a id="decision-170"></a>[170](decisions/0170-the-package-exports-one-module-colibri.md) | The package exports one module, `colibri`, whose root names each library module. |
| <a id="decision-171"></a>[171](decisions/0171-colibri-takes-stdxs-one-module-stdx.md) | colibri takes stdx's one module, `stdx`. |
| <a id="decision-172"></a>[172](decisions/0172-colibri-asks-chapulin-once-and-chapulins.md) | colibri asks chapulin once, and chapulin's module defines `ch_assert_fail`. |
| <a id="decision-173"></a>[173](decisions/0173-a-servers-udp-socket-shares-its.md) | A server's UDP socket shares its port with SO_REUSEPORT. |
| <a id="decision-174"></a>[174](decisions/0174-colibri-takes-chapulin-through-stdx-as.md) | colibri takes chapulin through stdx, as `stdx.crypto`. |
| <a id="decision-175"></a>[175](decisions/0175-colibri-takes-the-programs-stdxcryptocontext-once.md) | colibri takes the program's `stdx.crypto.Context` once, in the TLS values. |
| <a id="decision-176"></a>[176](decisions/0176-a-tcp-socket-sends-from-its.md) | A TCP socket sends from its connection's output, through `output_stream` and `sent_stream`. |
