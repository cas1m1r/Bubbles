CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
LDFLAGS ?= -lseccomp -lpthread

all: seccomp_launcher

seccomp_launcher: seccomp_launcher.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f seccomp_launcher
