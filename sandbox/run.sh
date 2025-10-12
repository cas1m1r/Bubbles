make clean && make


# plain run
./seccomp_launcher -- /bin/sh -c 'echo ok'

# notify path (now works; you'll see a process.spawn log)
./seccomp_launcher --notify-exec -- /bin/sh -c 'echo ok'

# your script with errno + log-continue
./seccomp_launcher --log-continue --mode=errno --notify-exec ./simple_test.sh
