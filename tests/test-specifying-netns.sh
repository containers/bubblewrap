#!/usr/bin/env bash

set -xeuo pipefail

srcd=$(cd $(dirname "$0") && pwd)
. "${srcd}/libtest.sh"

echo "1..1"

# This test needs user namespaces
if test -n "${bwrap_is_suid:-}"; then
    echo "ok - # SKIP no setuid support for --unshare-user"
else
    # Start the server inside a bubblewrap sandbox with a new user and net namespace
    $RUN --info-fd 42 --unshare-user --unshare-net python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 0))
port = s.getsockname()[1]
with open('server-port.txt', 'w') as f:
    f.write(str(port))
s.listen(1)
conn, addr = s.accept()
conn.sendall(b'hello from netns\n')
conn.close()
" 42>info.json &

    # Wait for the server to write the port file
    while ! test -f server-port.txt; do sleep 0.1; done
    SANDBOX1PID=$(extract_child_pid info.json)

    # Run the client inside another bubblewrap sandbox, joining the user and net namespaces of the first
    ASAN_OPTIONS=detect_leaks=0 LSAN_OPTIONS=detect_leaks=0 \
    $RUN --userns 11 --netns 12 python3 -c "
import socket
with open('server-port.txt', 'r') as f:
    port = int(f.read().strip())
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', port))
data = s.recv(1024)
print(data.decode().strip())
s.close()
" 11< /proc/$SANDBOX1PID/ns/user 12< /proc/$SANDBOX1PID/ns/net > client-output.txt

    # Verify the output
    echo "hello from netns" > expected.txt
    assert_files_equal expected.txt client-output.txt

    rm -f info.json server-port.txt client-output.txt expected.txt

    echo "ok - Test --netns"
fi
