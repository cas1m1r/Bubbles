#!/bin/bash
set -e

echo "=== Building Project Bubble Sandbox ==="
make clean && make

echo ""
echo "=== Test 1: Basic execution (should succeed) ==="
./seccomp_launcher -- /bin/echo "Hello from sandbox"

echo ""
echo "=== Test 2: Blocked file write (default policy) ==="
./seccomp_launcher --mode=errno --log-errno --log-continue -- \
    /bin/sh -c 'echo "attempting write..." && echo test > /tmp/blocked.txt; echo "done"'

echo ""
echo "=== Test 3: Allowed file write (with permission) ==="
./seccomp_launcher --allow-fs-write --mode=errno -- \
    /bin/sh -c 'echo "writing with permission..." && echo test > /tmp/allowed.txt && cat /tmp/allowed.txt'

echo ""
echo "=== Test 4: Network blocking (default) ==="
./seccomp_launcher --mode=errno --log-continue -- \
    /bin/sh -c 'echo "trying to create socket..." && nc -z 127.0.0.1 80; echo "done"' || true

echo ""
echo "=== Test 5: Network allowed ==="
./seccomp_launcher --allow-network --mode=errno -- \
    /bin/sh -c 'echo "creating socket with permission..." && timeout 1 nc -z 127.0.0.1 80; echo "done"' || true

echo ""
echo "=== Test 6: Process spawn notification ==="
./seccomp_launcher --notify-exec --mode=errno -- \
    /bin/sh -c 'echo parent; /bin/echo child; echo done'

echo ""
echo "=== Test 7: Running test_violations binary ==="
if [ -f ./test_violations ]; then
    ./seccomp_launcher --log-continue --mode=errno --log-errno ./test_violations
else
    echo "test_violations not found, skipping"
fi

echo ""
echo "=== Test 8: Detailed violation logging ==="
./seccomp_launcher --mode=errno --log-errno --log-continue -- \
    /bin/sh -c '
        echo "[test] Attempting various operations..."
        touch /tmp/test1.txt 2>&1 || echo "  ✗ touch blocked"
        mkdir /tmp/testdir 2>&1 || echo "  ✗ mkdir blocked"
        rm /tmp/nonexistent 2>&1 || echo "  ✗ rm blocked"
        echo "[test] All operations attempted"
    '

echo ""
echo "=== All tests complete! ==="
echo "Now start the Flask UI with: cd orchestrator && python3 app.py"