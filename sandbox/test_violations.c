// A tiny program to demonstrate sandbox denials:
// 1) tries to create a file (should fail via RLIMIT_FSIZE or openat write denial)
// 2) tries to create a socket (should get killed by seccomp)
#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    puts("[test] attempting write to file...");
    int fd = open("should_not_exist.txt", O_WRONLY|O_CREAT, 0644);
    if (fd == -1) perror("open (expected failure)");
    else { write(fd, "nope\n", 5); close(fd); }

    puts("[test] attempting socket()...");
    int s = socket(AF_INET, SOCK_STREAM, 0); // should trigger seccomp kill
    (void)s;
    return 0;
}
