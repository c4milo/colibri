"""Judges one QUIC Interop Runner result file, which tools/interop.sh has the runner write with -j.

A case a peer fails on its own side is listed below with the reason (decision 112). It is reported
and does not fail the run. Every other failed case fails the run. A listed case that did not fail
is reported too, because its entry can then be removed.

    known_failures.py <result.json>

It prints one line for each listed case the run holds, and exits 1 when a case outside the list
failed or the file does not read, and 0 otherwise.
"""
import json
import sys

# (server, client, the runner's abbreviation of the test case), each with why the peer fails it.
KNOWN_FAILURES = {
    # quinn's client runs the v2 case with no version_information in its ClientHello, which RFC
    # 9369 §4 requires of an endpoint that supports version 2. RFC 9368 §2.3 has a server choose
    # from the versions the client lists, so colibri's server keeps it in version 1.
    ("colibri", "quinn", "V2"): "quinn's client sends no version_information (RFC 9369 §4)",
}


def cases(result):
    """Yields (server, client, abbreviation, verdict) for every case in the file.

    The runner writes one list of cases per pair, the clients in the outer loop and the servers in
    the inner one, in the order its `clients` and `servers` arrays give (its _export_results).
    """
    servers = result["servers"]
    for client_index, client in enumerate(result["clients"]):
        for server_index, server in enumerate(servers):
            for case in result["results"][client_index * len(servers) + server_index]:
                yield server, client, case["abbr"], case["result"]


def main(path):
    try:
        with open(path) as file:
            result = json.load(file)
        judged = list(cases(result))
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        print(f"interop: {path} does not read: {error}")
        return 1
    unlisted = 0
    for server, client, abbreviation, verdict in judged:
        reason = KNOWN_FAILURES.get((server, client, abbreviation))
        if reason is None:
            unlisted += verdict == "failed"
        elif verdict is None:
            # The runner did not run the case, for a peer it found not compliant.
            continue
        elif verdict == "failed":
            print(f"interop: {client}'s client against {server}'s server failed {abbreviation}, as decision 112 lists: {reason}")
        else:
            print(f"interop: {client}'s client against {server}'s server did not fail {abbreviation} ({verdict}), so decision 112's entry for it can be removed")
    if unlisted:
        print(f"interop: {unlisted} failed cases in {path} are not in decision 112's list")
    return 1 if unlisted else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
