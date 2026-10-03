#!/usr/bin/env bash
# Prints the port a peer listens on, once the peer's log names it. Every peer a check script
# starts binds port 0, so the kernel chooses a port no other process has, and two runs on one
# machine do not collide (https://github.com/c4milo/colibri/issues/94). A peer prints
# "listening on port <port>" once its socket is bound, which is also when a client may connect,
# so this is the scripts' wait for a peer too.
#
# Usage: tools/listening_port.sh <log> [seconds]
#        (the log holds no earlier peer's line; the wait is 30 seconds unless named)
set -euo pipefail

readonly log="${1:?usage: tools/listening_port.sh <log> [seconds]}"
readonly seconds="${2:-30}"
# The log is read ten times a second.
readonly reads_per_second=10

for _ in $(seq "$((seconds * reads_per_second))"); do
  port=""
  # A script starts its peer in the background, and the peer's shell creates the log: until it
  # has, there is nothing to read, which is not a failure.
  if [ -r "${log}" ]; then
    port="$(sed -n 's/.*listening on port \([0-9][0-9]*\).*/\1/p' "${log}" | head -1)"
  fi
  if [ -n "${port}" ]; then
    echo "${port}"
    exit 0
  fi
  sleep 0.1
done
echo "listening_port.sh: no peer listened within ${seconds} seconds, and ${log} holds:" >&2
cat "${log}" >&2 2>/dev/null || true
exit 1
