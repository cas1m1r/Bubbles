CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
LDFLAGS ?= -lseccomp -lpthread

all: seccomp_launcher test_violations

seccomp_launcher: seccomp_launcher.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_violations: test_violations.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f seccomp_launcher test_violations
