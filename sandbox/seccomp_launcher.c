// Defensive seccomp launcher (userspace NOTIFY; never hangs the parent)
// Build: gcc -O2 -Wall -Wextra -o seccomp_launcher seccomp_launcher.c -lseccomp -lpthread
// Usage: ./seccomp_launcher [--pidns] [--deny-fs=1|0] [--deny-net=1|0] [--notify-exec] [--diagnose] -- <program> [args...]

#define _GNU_SOURCE
#include <linux/seccomp.h>
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE 1
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__x86_64__)
# error "This demo targets x86_64."
#endif

/* ----------------- globals / knobs ----------------- */
static int g_deny_fs     = 1;  // deny filesystem mutations (via NOTIFY)
static int g_deny_net    = 1;  // deny networking (via NOTIFY)
static int g_notify_exec = 0;  // log & allow exec via NOTIFY
static int g_diagnose    = 0;  // ask kernel to LOG filter matches

/* supervisor NOTIFY fd (so parent can stop thread) */
static int g_notify_fd = -1;

/* ----------------- small utils ----------------- */
static void jlog(const char *fmt, ...) {
    // single-line JSON-ish log for easy parsing
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

static const char* timestr(char buf[64]) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm; gmtime_r(&ts.tv_sec, &tm);
    strftime(buf, 64, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

static const char *sys_name(int nr) {
    const char *n = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, nr);
    static char buf[32];
    if (n) return n;
    snprintf(buf, sizeof(buf), "#%d", nr);
    return buf;
}

static void set_limits(void) {
    struct rlimit rl;

    // modest CPU cap so runaways end quickly
    rl.rlim_cur=2; rl.rlim_max=2; setrlimit(RLIMIT_CPU, &rl);
    // reasonable address space
    rl.rlim_cur=128*1024*1024; rl.rlim_max=128*1024*1024; setrlimit(RLIMIT_AS, &rl);
    // IMPORTANT: do NOT set FSIZE=0 — it breaks shells/scripts and echo/ls
    rl.rlim_cur = rl.rlim_max = (rlim_t)(1ULL<<40);   // ~1 TB; effectively no limit
    setrlimit(RLIMIT_FSIZE, &rl);
    // smallish fd/process limits
    rl.rlim_cur=64; rl.rlim_max=64; setrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur=0;  rl.rlim_max=0;  setrlimit(RLIMIT_CORE, &rl);
}

/* -------- fd passing helpers (UNIX sockets) -------- */
static int send_fd(int sock, int fd) {
    struct msghdr msg = {0};
    char buf[CMSG_SPACE(sizeof(fd))]; memset(buf, 0, sizeof(buf));
    struct iovec io = { .iov_base=(void*)"F", .iov_len=1 };
    msg.msg_iov     = &io; msg.msg_iovlen = 1;
    msg.msg_control = buf; msg.msg_controllen = sizeof(buf);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level=SOL_SOCKET; cmsg->cmsg_type=SCM_RIGHTS; cmsg->cmsg_len=CMSG_LEN(sizeof(fd));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    msg.msg_controllen = CMSG_SPACE(sizeof(fd));
    return sendmsg(sock, &msg, 0);
}

static int recv_fd_nonblock(int sock, int timeout_ms) {
    struct pollfd p = { .fd=sock, .events=POLLIN };
    int pr = poll(&p, 1, timeout_ms);
    if (pr <= 0) return -1; // timeout or error

    struct msghdr msg = {0};
    char m_buffer[1];
    struct iovec io = { .iov_base=m_buffer, .iov_len=sizeof(m_buffer) };
    msg.msg_iov=&io; msg.msg_iovlen=1;
    char c_buffer[CMSG_SPACE(sizeof(int))];
    msg.msg_control=c_buffer; msg.msg_controllen=sizeof(c_buffer);

    if (recvmsg(sock, &msg, 0) < 0) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return -1;
    int fd; memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd)); return fd;
}

/* ---------- remote read helpers (for pretty logs) ---------- */
static ssize_t read_remote(pid_t pid, const void *addr, void *out, size_t len) {
    struct iovec l = { .iov_base = out, .iov_len = len };
    struct iovec r = { .iov_base = (void*)addr, .iov_len = len };
    return syscall(SYS_process_vm_readv, pid, &l, 1, &r, 1, 0);
}

static ssize_t read_remote_string(pid_t pid, const void *addr, char *out, size_t maxlen) {
    if (!addr) { out[0]='\0'; return 0; }
    size_t off=0;
    while (off < maxlen-1) {
        if (read_remote(pid, (const char*)addr+off, out+off, 1) != 1) break;
        if (!out[off]) return off;
        off++;
    }
    out[maxlen-1]='\0'; return off;
}

/* ---------- NOTIFY logging helpers ---------- */
static void log_open_like(int scno, pid_t tpid, const void *pathptr, int flags, int mode) {
    char path[256]={0}; char ts[64];
    read_remote_string(tpid, pathptr, path, sizeof(path));
    timestr(ts);
    jlog("{\"type\":\"policy.alert\",\"reason\":\"errno\",\"category\":\"fs\","
         "\"syscall\":\"%s\",\"syscall_no\":%d,\"ts\":\"%s\","
         "\"path\":\"%s\",\"flags\":%d,\"mode\":%d,\"denied\":\"EPERM\"}",
         sys_name(scno), scno, ts, path, flags, mode);
}

static void log_connect(int scno, pid_t tpid, const void *saptr, socklen_t slen) {
    char peer[128] = {0}; int port = -1; short fam = -1;
    unsigned char buf[128]; size_t n = (slen > sizeof(buf)) ? sizeof(buf) : slen;
    if (saptr && n >= sizeof(sa_family_t) && read_remote(tpid, saptr, buf, n) == (ssize_t)n) {
        const struct sockaddr *sa = (const struct sockaddr*)buf;
        fam = sa->sa_family;
        if (fam == AF_INET && n >= sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *in = (const struct sockaddr_in*)sa;
            inet_ntop(AF_INET, &in->sin_addr, peer, sizeof(peer));
            port = ntohs(in->sin_port);
        } else if (fam == AF_INET6 && n >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *in6 = (const struct sockaddr_in6*)sa;
            inet_ntop(AF_INET6, &in6->sin6_addr, peer, sizeof(peer));
            port = ntohs(in6->sin6_port);
        } else if (fam == AF_UNIX) {
            snprintf(peer, sizeof(peer), "unix");
        } else {
            snprintf(peer, sizeof(peer), "family=%d", fam);
        }
    } else {
        snprintf(peer, sizeof(peer), "<unreadable>");
    }
    char ts[64]; timestr(ts);
    jlog("{\"type\":\"policy.alert\",\"reason\":\"errno\",\"category\":\"net\","
         "\"syscall\":\"connect\",\"syscall_no\":%d,\"ts\":\"%s\","
         "\"peer\":\"%s\",\"port\":%d,\"family\":%d,\"denied\":\"EPERM\"}",
         scno, ts, peer, port, fam);
}

/* --- replace original supervisor_thread's core loop with this forwarding variant --- */

static void *supervisor_thread(void *arg) {
    int nfd = (int)(intptr_t)arg; g_notify_fd = nfd;

    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;
    if (seccomp_notify_alloc(&req, &resp) != 0) return NULL;

    /* check for external supervisor socket FD via env var */
    int sup_fd = -1;
    const char *supfd_env = getenv("SUPERVISOR_JSON_FD");
    if (supfd_env) {
        sup_fd = atoi(supfd_env);
        if (sup_fd < 0) sup_fd = -1;
    }

    for (;;) {
        if (seccomp_notify_receive(nfd, req) != 0) break;

        int scno = req->data.nr;
        pid_t tpid = req->pid;

        /* Fast path: if there's an external supervisor socket, forward a compact JSON and wait */
        if (sup_fd >= 0) {
            char outbuf[2048];
            char inbuf[512];
            int outlen = 0;

            /* Build a small JSON describing the syscall */
            const char *sname = sys_name(scno);
            /* default fields */
            snprintf(outbuf, sizeof(outbuf),
                "{\"type\":\"notify\",\"syscall\":\"%s\",\"syscall_no\":%d,\"pid\":%d",
                sname, scno, tpid);
            outlen = strlen(outbuf);

            /* add syscall-specific fields we can read (best-effort) */
            if (scno == __NR_openat || scno == __NR_open) {
                char path[256] = {0};
                const void *pathptr = (scno == __NR_openat) ? (const void *)req->data.args[1] : (const void *)req->data.args[0];
                read_remote_string(tpid, pathptr, path, sizeof(path));
                int flags = (int)((scno == __NR_openat) ? req->data.args[2] : req->data.args[1]);
                int mode  = (int)((scno == __NR_openat) ? req->data.args[3] : req->data.args[2]);
                outlen += snprintf(outbuf + outlen, sizeof(outbuf)-outlen,
                    ",\"path\":\"%s\",\"flags\":%d,\"mode\":%d", path, flags, mode);
            } else if (scno == __NR_connect) {
                /* read sockaddr from remote process memory (best-effort) */
                char peer[128] = {0};
                int port = -1;
                log_connect(scno, tpid, (const void*)req->data.args[1], (socklen_t)req->data.args[2]);
                /* note: we already logged; now attempt to extract ip/port */
                unsigned char buf[128]; size_t n = (size_t)req->data.args[2];
                if (n > sizeof(buf)) n = sizeof(buf);
                if (req->data.args[1] && read_remote(tpid, (const void*)req->data.args[1], buf, n) == (ssize_t)n) {
                    const struct sockaddr *sa = (const struct sockaddr*)buf;
                    if (sa->sa_family == AF_INET && n >= sizeof(struct sockaddr_in)) {
                        const struct sockaddr_in *in = (const struct sockaddr_in*)sa;
                        inet_ntop(AF_INET, &in->sin_addr, peer, sizeof(peer));
                        port = ntohs(in->sin_port);
                    }
                }
                outlen += snprintf(outbuf + outlen, sizeof(outbuf)-outlen,
                    ",\"peer\":\"%s\",\"port\":%d", peer[0]?peer:"<unk>", port);
            } else if (scno == __NR_unlinkat) {
                char path[256] = {0};
                read_remote_string(tpid, (const void*)req->data.args[1], path, sizeof(path));
                outlen += snprintf(outbuf + outlen, sizeof(outbuf)-outlen, ",\"path\":\"%s\"", path);
            }

            /* close JSON */
            outlen += snprintf(outbuf + outlen, sizeof(outbuf)-outlen, "}\n");

            /* send to orchestrator; block until write completes */
            ssize_t w = write(sup_fd, outbuf, outlen);
            if (w <= 0) {
                /* fallback: deny to be safe */
                resp->id = req->id; resp->error = -EPERM; resp->val = 0; resp->flags = 0;
                seccomp_notify_respond(nfd, resp);
                continue;
            }

            /* read one-line JSON reply from orchestrator */
            ssize_t r = read(sup_fd, inbuf, sizeof(inbuf)-1);
            if (r <= 0) {
                resp->id = req->id; resp->error = -EPERM; resp->val = 0; resp->flags = 0;
                seccomp_notify_respond(nfd, resp);
                continue;
            }
            inbuf[r] = '\0';
            /* crude parsing: look for action keys */
            if (strstr(inbuf, "\"action\":\"ALLOW\"") || strstr(inbuf, "\"action\": \"ALLOW\"")) {
                resp->id = req->id; resp->error = 0; resp->val = 0; resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                seccomp_notify_respond(nfd, resp);
                continue;
            } else if (strstr(inbuf, "\"action\":\"DENY_ERRNO\"") || strstr(inbuf, "\"action\": \"DENY_ERRNO\"")) {
                /* parse errno if present */
                int err = EPERM;
                char *p = strstr(inbuf, "\"errno\":");
                if (p) err = atoi(p + 8);
                resp->id = req->id; resp->error = -err; resp->val = 0; resp->flags = 0;
                seccomp_notify_respond(nfd, resp);
                continue;
            } else if (strstr(inbuf, "\"action\":\"EMULATE_RET\"") || strstr(inbuf, "\"action\": \"EMULATE_RET\"")) {
                /* parse ret value */
                int retv = 0;
                char *p = strstr(inbuf, "\"ret\":");
                if (p) retv = atoi(p + 6);
                resp->id = req->id; resp->error = 0; resp->val = retv; resp->flags = 0;
                seccomp_notify_respond(nfd, resp);
                continue;
            } else if (strstr(inbuf, "\"action\":\"QUARANTINE\"") || strstr(inbuf, "\"action\": \"QUARANTINE\"")) {
                resp->id = req->id; resp->error = -EPERM; resp->val = 0; resp->flags = 0;
                seccomp_notify_respond(nfd, resp);
                /* optionally log quarantine locally */
                char ts[64]; timestr(ts);
                jlog("{\"type\":\"policy.alert\",\"reason\":\"quarantine\",\"syscall\":\"%s\",\"syscall_no\":%d,\"pid\":%d,\"ts\":\"%s\"}",
                     sname, scno, tpid, ts);
                continue;
            } else {
                /* unknown reply => safe deny */
                resp->id = req->id; resp->error = -EPERM; resp->val = 0; resp->flags = 0;
                seccomp_notify_respond(nfd, resp);
                continue;
            }
        } /* end sup_fd >= 0 */

        /* --- fallback: original internal policy (unchanged) --- */
        if (g_notify_exec && (scno == __NR_execve || scno == __NR_execveat)) {
            char path[256]={0}; char ts[64];
            const void *p = (const void *)(req->data.args[0]); // pathname
            read_remote_string(tpid, p, path, sizeof(path));
            timestr(ts);
            jlog("{\"type\":\"process.spawn\",\"syscall\":\"%s\",\"pid\":%d,\"exe\":\"%s\",\"ts\":\"%s\"}",
                sys_name(scno), tpid, path[0]?path:"<unknown>", ts);
            resp->id = req->id;
            resp->val = 0;
            resp->error = 0;
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            (void)seccomp_notify_respond(nfd, resp);
            continue;
        }

        /* FS denials (log, then EPERM) */
        if (g_deny_fs) {
            if (scno == __NR_openat) {
                log_open_like(scno, tpid, (const void*)req->data.args[1],
                              (int)req->data.args[2], (int)req->data.args[3]);
                goto deny;
            }
#ifdef __NR_open
            if (scno == __NR_open) {
                log_open_like(scno, tpid, (const void*)req->data.args[0],
                              (int)req->data.args[1], (int)req->data.args[2]);
                goto deny;
            }
#endif
#ifdef __NR_unlinkat
            if (scno == __NR_unlinkat) {
                char path[256]={0}; char ts[64];
                read_remote_string(tpid, (const void*)req->data.args[1], path, sizeof(path));
                timestr(ts);
                jlog("{\"type\":\"policy.alert\",\"reason\":\"errno\",\"category\":\"fs\","
                     "\"syscall\":\"unlinkat\",\"syscall_no\":%d,\"ts\":\"%s\","
                     "\"path\":\"%s\",\"denied\":\"EPERM\"}", scno, ts, path);
                goto deny;
            }
#endif
        }

        /* NET denials (log, then EPERM) */
        if (g_deny_net) {
            if (scno == __NR_socket) {
                int dom=(int)req->data.args[0], type=(int)req->data.args[1], proto=(int)req->data.args[2];
                char ts[64]; timestr(ts);
                jlog("{\"type\":\"policy.alert\",\"reason\":\"errno\",\"category\":\"net\","
                     "\"syscall\":\"socket\",\"syscall_no\":%d,\"ts\":\"%s\","
                     "\"domain\":%d,\"type\":%d,\"proto\":%d,\"denied\":\"EPERM\"}",
                     scno, ts, dom, type, proto);
                goto deny;
            }
            if (scno == __NR_connect) {
                log_connect(scno, tpid, (const void*)req->data.args[1], (socklen_t)req->data.args[2]);
                goto deny;
            }
        }

deny:
        resp->id = req->id; resp->error = -EPERM; resp->val = 0; resp->flags = 0;
        if (seccomp_notify_respond(nfd, resp) != 0) break;
    }

    seccomp_notify_free(req, resp);
    return NULL;
}

/* ---------- namespaces ---------- */
static void maybe_unshare_pidns(bool enabled) {
    if (enabled && unshare(CLONE_NEWPID)!=0) perror("unshare(CLONE_NEWPID)");
}

/* ---------- allowlist (stdio, read-only fs, etc.) ---------- */
static void allow_common(scmp_filter_ctx ctx) {
    // lifecycle/signals
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigaltstack), 0);

    // stdio / fcntl (make echo/ls actually print)
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup3), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);

    // memory/time/threads
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);

    // ids/env/infos
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);

    // read-only fs
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statx), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlinkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat), 0);
#ifdef __NR_faccessat2
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat2), 0);
#endif

    // proc control
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(waitid), 0);

    // timers
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setitimer), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);

    // fd passing for supervisor socket
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
}

/* ---------- install filter (returns ctx already loaded) ---------- */
static scmp_filter_ctx install_filter(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) { perror("seccomp_init"); exit(1); }

    if (g_diagnose) seccomp_attr_set(ctx, SCMP_FLTATR_CTL_LOG, 1);

    allow_common(ctx);

    /* Filesystem write-like -> NOTIFY if requested */
    if (g_deny_fs) {
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 1,
            SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_ACCMODE, O_WRONLY));
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 1,
            SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDWR));
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 1,
            SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_CREAT, O_CREAT));
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 1,
            SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_TRUNC, O_TRUNC));
#ifdef __NR_unlinkat
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(unlinkat), 0);
#endif
#ifdef __NR_open
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(open), 1,
            SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_ACCMODE, O_WRONLY));
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(open), 1,
            SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDWR));
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(open), 1,
            SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_CREAT, O_CREAT));
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(open), 1,
            SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_TRUNC, O_TRUNC));
#endif
    }

    /* Networking -> NOTIFY if requested */
    if (g_deny_net) {
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(socket), 0);
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(connect), 0);
    }

    /* Exec: default ALLOW; optionally NOTIFY for visibility only */
    if (g_notify_exec) {
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(execve), 0);
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(execveat), 0);
    } else {
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execveat), 0);
    }

    if (seccomp_load(ctx) != 0) { perror("seccomp_load"); exit(1); }
    return ctx;
}

/* ----------------- CLI & main ----------------- */
static void usage(const char *p) {
    fprintf(stderr,
      "Usage: %s [--pidns] [--deny-fs=1|0] [--deny-net=1|0] [--notify-exec] [--diagnose] -- <program> [args...]\n"
      "Behavior: disallowed actions are denied with EPERM and logged via seccomp USER NOTIFY.\n", p);
    exit(2);
}

int main(int argc, char **argv) {
    bool pidns=false; int i=1;
    for (; i<argc; ++i) {
        if (!strcmp(argv[i],"--pidns")) pidns=true;
        else if (!strncmp(argv[i],"--deny-fs=",10)) g_deny_fs = atoi(argv[i]+10)!=0;
        else if (!strncmp(argv[i],"--deny-net=",11)) g_deny_net = atoi(argv[i]+11)!=0;
        else if (!strcmp(argv[i],"--notify-exec")) g_notify_exec=1;
        else if (!strcmp(argv[i],"--diagnose")) g_diagnose=1;
        else if (!strcmp(argv[i],"--")) { ++i; break; }
        else break;
    }
    if (i>=argc) usage(argv[0]);
    char **target = &argv[i];

    if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return 1;
    }

    maybe_unshare_pidns(pidns);
    set_limits();

    // upfront log so the orchestrator always sees something immediately
    { char ts[64]; timestr(ts);
      jlog("{\"type\":\"process.spawn\",\"exe\":\"%s\",\"ts\":\"%s\"}", target[0], ts);
    }

    int need_notify = (g_deny_fs || g_deny_net || g_notify_exec);

    int sv[2] = {-1,-1};
    if (need_notify && socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)!=0) {
        perror("socketpair"); need_notify = 0;
    }

    pid_t pid=fork();
    if (pid<0) { perror("fork"); return 1; }

    if (pid==0) {
        // child
        if (need_notify) close(sv[0]);
        scmp_filter_ctx ctx = install_filter();

        if (need_notify) {
            int nfd = seccomp_notify_fd(ctx);
            if (nfd >= 0) {
                if (send_fd(sv[1], nfd) < 0) {
                    // best effort: if send fails, just continue; parent will fall back
                }
                close(nfd);
            }
            close(sv[1]);
        }

        execvp(target[0], target);
        perror("execvp");
        _exit(127);
    }

    // parent
    int nfd = -1; pthread_t th = 0;
    if (need_notify) {
        close(sv[1]);
        // DO NOT BLOCK FOREVER: poll for up to 1000ms for the FD
        nfd = recv_fd_nonblock(sv[0], 1000);
        close(sv[0]);
        if (nfd >= 0) {
            (void)pthread_create(&th, NULL, supervisor_thread, (void*)(intptr_t)nfd);
        }
    }

    int status=0;
    if (waitpid(pid,&status,0) < 0) { perror("waitpid"); }

    // stop supervisor cleanly (if it ever started)
    if (nfd >= 0) close(nfd);
    if (th) pthread_join(th, NULL);

    if (WIFEXITED(status)) {
        jlog("{\"type\":\"sandbox.msg\",\"action\":\"exit\",\"code\":%d}", WEXITSTATUS(status));
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        jlog("{\"type\":\"sandbox.msg\",\"action\":\"signal\",\"sig\":%d}", WTERMSIG(status));
        return 128+WTERMSIG(status);
    }
    jlog("{\"type\":\"sandbox.msg\",\"action\":\"exit\",\"unknown\":true}");
    return 1;
}
