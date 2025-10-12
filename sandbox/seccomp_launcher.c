// Enhanced seccomp sandbox launcher with configurable permissions
// Build: gcc -O2 -Wall -Wextra -o seccomp_launcher seccomp_launcher.c -lseccomp -lpthread
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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
#include <sys/ucontext.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#if !defined(__x86_64__)
# error "This demo targets x86_64."
#endif

/* ---------- utils ---------- */
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fprintf(stderr, "\n"); exit(1);
}
static const char* timestr(char buf[64]) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm; gmtime_r(&ts.tv_sec, &tm); strftime(buf, 64, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

/* ---------- limits ---------- */
static void set_limits(bool diagnose) {
    struct rlimit rl;
    rl.rlim_cur=2; rl.rlim_max=2; setrlimit(RLIMIT_CPU, &rl);
    rl.rlim_cur=128*1024*1024; rl.rlim_max=128*1024*1024; setrlimit(RLIMIT_AS, &rl);
    if (diagnose) { rl.rlim_cur = rl.rlim_max = (rlim_t)(1ULL<<40); }
    else          { rl.rlim_cur=0; rl.rlim_max=0; }
    setrlimit(RLIMIT_FSIZE, &rl);
    rl.rlim_cur=64; rl.rlim_max=64; setrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur=0; rl.rlim_max=0; setrlimit(RLIMIT_CORE, &rl);
}

/* ---------- arg extraction (x86_64) ---------- */
static inline unsigned long get_arg_u64(const ucontext_t *uc, int idx) {
    switch (idx) {
        case 0: return uc->uc_mcontext.gregs[REG_RDI];
        case 1: return uc->uc_mcontext.gregs[REG_RSI];
        case 2: return uc->uc_mcontext.gregs[REG_RDX];
        case 3: return uc->uc_mcontext.gregs[REG_R10];
        case 4: return uc->uc_mcontext.gregs[REG_R8];
        case 5: return uc->uc_mcontext.gregs[REG_R9];
        default: return 0;
    }
}
static void copy_path_safely(const char *p, char out[256]) {
    if (!p) { strcpy(out, "<null>"); return; }
    size_t i; for (i=0;i<255;i++){ char c=p[i]; if(!c) break; out[i]=(c<32)?'?':c; } out[i]='\0';
}

/* ---------- decoding helpers ---------- */
static const char *sys_name(int nr) {
    const char *n = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, nr);
    static char buf[32];
    if (n) return n;
    snprintf(buf, sizeof(buf), "#%d", nr);
    return buf;
}
static void flags_to_str_open(int flags, char *out, size_t n) {
    struct { int v; const char *name; } tbl[] = {
        { O_RDONLY, "O_RDONLY" }, { O_WRONLY, "O_WRONLY" }, { O_RDWR, "O_RDWR" },
        { O_CREAT, "O_CREAT" }, { O_TRUNC, "O_TRUNC" }, { O_EXCL, "O_EXCL" },
#ifdef O_TMPFILE
        { O_TMPFILE, "O_TMPFILE" },
#endif
        { O_APPEND, "O_APPEND" }, { O_CLOEXEC, "O_CLOEXEC" }, { O_DIRECTORY, "O_DIRECTORY" },
        { O_NOFOLLOW, "O_NOFOLLOW" }
    };
    int acc = flags & O_ACCMODE;
    size_t off = 0; out[0]='\0';
    if (acc == O_RDONLY) off += snprintf(out+off, n-off, "O_RDONLY");
    else if (acc == O_WRONLY) off += snprintf(out+off, n-off, "O_WRONLY");
    else if (acc == O_RDWR)   off += snprintf(out+off, n-off, "O_RDWR");
    for (size_t i=0;i<sizeof(tbl)/sizeof(tbl[0]);++i) {
        if (tbl[i].v==O_RDONLY || tbl[i].v==O_WRONLY || tbl[i].v==O_RDWR) continue;
        if (flags & tbl[i].v) off += snprintf(out+off, n-off, "%s%s", off? "|":"", tbl[i].name);
    }
    if (off==0) snprintf(out, n, "0");
}
static const char* dom_to_str(int d) {
    switch(d){case AF_UNIX:return"AF_UNIX";case AF_INET:return"AF_INET";case AF_INET6:return"AF_INET6";default:return"AF_?";}
}
static const char* socktype_to_str(int t) {
    switch(t){case SOCK_STREAM:return"SOCK_STREAM";case SOCK_DGRAM:return"SOCK_DGRAM";case SOCK_RAW:return"SOCK_RAW";default:return"SOCK_?";}
}

/* ---------- global knobs ---------- */
typedef enum { VMODE_TRAP, VMODE_ERRNO } viol_mode_t;

static int g_continue_on_trap = 0;
static int g_log_errno_fs = 0;
static int g_notify_exec = 0;

/* NEW: Permission flags */
static int g_allow_fs_write = 0;
static int g_allow_network = 0;

/* ---------- SIGSYS handler for TRAP ---------- */
static void sigsys_handler(int nr, siginfo_t *si, void *uctx) {
    (void)nr;
    ucontext_t *uc = (ucontext_t*)uctx;
    int sysno = si ? si->si_syscall : -1;
    char ts[64]; timestr(ts);

    switch (sysno) {
        case __NR_openat: {
            (void)get_arg_u64(uc,0);
            const char *pathname=(const char*)get_arg_u64(uc,1);
            int flags=(int)get_arg_u64(uc,2);
            int mode =(int)get_arg_u64(uc,3);
            char pathbuf[256]; copy_path_safely(pathname, pathbuf);
            char fbuf[256]; flags_to_str_open(flags, fbuf, sizeof fbuf);
            fprintf(stderr,
                "{\"type\":\"policy.alert\",\"reason\":\"trap\",\"category\":\"fs\",\"syscall\":\"%s\",\"syscall_no\":%d,"
                "\"ts\":\"%s\",\"path\":\"%s\",\"flags\":\"%s\",\"mode\":%d}\n",
                sys_name(sysno), sysno, ts, pathbuf, fbuf, mode);
        } break;
#ifdef __NR_open
        case __NR_open: {
            const char *pathname=(const char*)get_arg_u64(uc,0);
            int flags=(int)get_arg_u64(uc,1);
            int mode =(int)get_arg_u64(uc,2);
            char pathbuf[256]; copy_path_safely(pathname, pathbuf);
            char fbuf[256]; flags_to_str_open(flags, fbuf, sizeof fbuf);
            fprintf(stderr,
                "{\"type\":\"policy.alert\",\"reason\":\"trap\",\"category\":\"fs\",\"syscall\":\"%s\",\"syscall_no\":%d,"
                "\"ts\":\"%s\",\"path\":\"%s\",\"flags\":\"%s\",\"mode\":%d}\n",
                sys_name(sysno), sysno, ts, pathbuf, fbuf, mode);
        } break;
#endif
        case __NR_unlinkat: {
            (void)get_arg_u64(uc,0);
            const char *pathname=(const char*)get_arg_u64(uc,1);
            int flags=(int)get_arg_u64(uc,2);
            char pathbuf[256]; copy_path_safely(pathname, pathbuf);
            fprintf(stderr,
                "{\"type\":\"policy.alert\",\"reason\":\"trap\",\"category\":\"fs\",\"syscall\":\"%s\",\"syscall_no\":%d,"
                "\"ts\":\"%s\",\"path\":\"%s\",\"flags\":%d}\n",
                sys_name(sysno), sysno, ts, pathbuf, flags);
        } break;
#ifdef __NR_renameat2
        case __NR_renameat2: {
            (void)get_arg_u64(uc,0); const char *oldp=(const char*)get_arg_u64(uc,1);
            (void)get_arg_u64(uc,2); const char *newp=(const char*)get_arg_u64(uc,3);
            int flags=(int)get_arg_u64(uc,4);
            char o[256], n[256]; copy_path_safely(oldp,o); copy_path_safely(newp,n);
            fprintf(stderr,
                "{\"type\":\"policy.alert\",\"reason\":\"trap\",\"category\":\"fs\",\"syscall\":\"%s\",\"syscall_no\":%d,"
                "\"ts\":\"%s\",\"old\":\"%s\",\"new\":\"%s\",\"flags\":%d}\n",
                sys_name(sysno), sysno, ts, o, n, flags);
        } break;
#endif
        case __NR_socket: {
            int dom=(int)get_arg_u64(uc,0), type=(int)get_arg_u64(uc,1), proto=(int)get_arg_u64(uc,2);
            fprintf(stderr,"{\"type\":\"policy.alert\",\"reason\":\"trap\",\"category\":\"net\",\"syscall\":\"%s\",\"syscall_no\":%d,"
                           "\"ts\":\"%s\",\"domain\":\"%s\",\"type\":\"%s\",\"proto\":%d}\n",
                    sys_name(sysno), sysno, ts, dom_to_str(dom), socktype_to_str(type), proto);
        } break;
        case __NR_connect: {
            int fd = (int)get_arg_u64(uc,0);
            const struct sockaddr *sa = (const struct sockaddr*)get_arg_u64(uc,1);
            socklen_t slen = (socklen_t)get_arg_u64(uc,2);
            char peer[128] = {0}; int port = -1;
            if (sa && slen >= sizeof(sa->sa_family)) {
                if (sa->sa_family == AF_INET && slen >= sizeof(struct sockaddr_in)) {
                    const struct sockaddr_in *in = (const struct sockaddr_in*)sa;
                    inet_ntop(AF_INET, &in->sin_addr, peer, sizeof(peer));
                    port = ntohs(in->sin_port);
                } else if (sa->sa_family == AF_INET6 && slen >= sizeof(struct sockaddr_in6)) {
                    const struct sockaddr_in6 *in6 = (const struct sockaddr_in6*)sa;
                    inet_ntop(AF_INET6, &in6->sin6_addr, peer, sizeof(peer));
                    port = ntohs(in6->sin6_port);
                } else if (sa->sa_family == AF_UNIX) {
                    snprintf(peer, sizeof(peer), "unix");
                } else snprintf(peer, sizeof(peer), "family=%d", sa->sa_family);
            } else snprintf(peer, sizeof(peer), "<bad-sockaddr>");
            fprintf(stderr,"{\"type\":\"policy.alert\",\"reason\":\"trap\",\"category\":\"net\",\"syscall\":\"%s\",\"syscall_no\":%d,"
                           "\"ts\":\"%s\",\"fd\":%d,\"peer\":\"%s\",\"port\":%d}\n",
                    sys_name(sysno), sysno, ts, fd, peer, port);
        } break;
        default:
            fprintf(stderr,"{\"type\":\"policy.alert\",\"reason\":\"trap\",\"syscall\":\"%s\",\"syscall_no\":%d,\"ts\":\"%s\"}\n",
                    sys_name(sysno), sysno, ts);
    }

    fflush(stderr);
    if (!g_continue_on_trap) _exit(137);
}

/* ---------- namespaces ---------- */
static void maybe_unshare_pidns(bool enabled) {
    if (enabled && unshare(CLONE_NEWPID)!=0) perror("unshare(CLONE_NEWPID)");
}

/* ---------- allowlist ---------- */
static void allow_common_dynbin(scmp_filter_ctx ctx) {
    // lifecycle/signals
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigaltstack), 0);

    // stdio/fcntl
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup3), 0);
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

    // ids/env
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);

    // fs lookup
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

    // misc benign
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0);
}

/* ---------- NOTIFY: fd passing & helpers ---------- */
static int send_fd(int sock, int fd) {
    struct msghdr msg = {0};
    char buf[CMSG_SPACE(sizeof(fd))]; memset(buf, 0, sizeof(buf));
    struct iovec io = { .iov_base=(void*)"F", .iov_len=1 };
    msg.msg_iov=&io; msg.msg_iovlen=1;
    msg.msg_control=buf; msg.msg_controllen=sizeof(buf);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level=SOL_SOCKET; cmsg->cmsg_type=SCM_RIGHTS; cmsg->cmsg_len=CMSG_LEN(sizeof(fd));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    msg.msg_controllen = CMSG_SPACE(sizeof(fd));
    return sendmsg(sock, &msg, 0);
}
static int recv_fd(int sock) {
    struct msghdr msg = {0};
    char m_buffer[1]; struct iovec io = { .iov_base=m_buffer, .iov_len=sizeof(m_buffer) };
    msg.msg_iov=&io; msg.msg_iovlen=1;
    char c_buffer[ CMSG_SPACE(sizeof(int)) ]; msg.msg_control=c_buffer; msg.msg_controllen=sizeof(c_buffer);
    if (recvmsg(sock, &msg, 0) < 0) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return -1;
    int fd; memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd)); return fd;
}
static ssize_t read_remote_string(pid_t pid, const void *addr, char *out, size_t maxlen) {
    size_t off=0;
    while (off < maxlen-1) {
        struct iovec local = { .iov_base = out+off, .iov_len = 1 };
        struct iovec remote= { .iov_base = (void*)((uintptr_t)addr+off), .iov_len = 1 };
        ssize_t n = syscall(SYS_process_vm_readv, pid, &local, 1, &remote, 1, 0);
        if (n != 1) break;
        if (out[off] == '\0') return off;
        off++;
    }
    out[maxlen-1]='\0'; return off;
}

/* ---------- NOTIFY supervisor ---------- */
static void *supervisor_thread(void *arg) {
    int nfd = (int)(intptr_t)arg;
    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;
    if (seccomp_notify_alloc(&req, &resp) != 0) return NULL;

    for (;;) {
        if (seccomp_notify_receive(nfd, req) != 0) break;
        int scno = req->data.nr; pid_t tpid = req->pid;
        char ts[64]; timestr(ts);

        /* --- exec visibility --- */
        if (g_notify_exec && (scno == __NR_execve || scno == __NR_execveat)) {
            char path[256]={0};
            const void *pathptr = (const void *)req->data.args[0];
            read_remote_string(tpid, pathptr, path, sizeof(path));
            fprintf(stderr,"{\"type\":\"process.spawn\",\"exe\":\"%s\",\"pid\":%d,\"ts\":\"%s\"}\n",
                    path[0]?path:"<unknown>", tpid, ts);
            fflush(stderr);
            resp->id = req->id; resp->val = 0; resp->error = 0; resp->flags = 0;
            if (seccomp_notify_respond(nfd, resp) != 0) break;
            continue;
        }

        /* --- FS errno logging via NOTIFY --- */
        if (g_log_errno_fs &&
            (scno == __NR_openat
#ifdef __NR_open
             || scno == __NR_open
#endif
#ifdef __NR_openat2
             || scno == __NR_openat2
#endif
             || scno == __NR_creat || scno == __NR_unlinkat
#ifdef __NR_renameat2
             || scno == __NR_renameat2
#endif
        )) {
            if (scno == __NR_openat) {
                const void *p = (const void*)req->data.args[1];
                int flags = (int)req->data.args[2];
                int mode  = (int)req->data.args[3];
                char path[256]={0}, fbuf[256];
                read_remote_string(tpid, p, path, sizeof(path));
                flags_to_str_open(flags, fbuf, sizeof fbuf);
                fprintf(stderr,
                    "{\"type\":\"policy.alert\",\"reason\":\"errno\",\"category\":\"fs\",\"syscall\":\"openat\",\"syscall_no\":%d,"
                    "\"ts\":\"%s\",\"path\":\"%s\",\"flags\":\"%s\",\"mode\":%d,\"denied\":\"EPERM\"}\n",
                    scno, ts, path, fbuf, mode);
            }
#ifdef __NR_open
            else if (scno == __NR_open) {
                const void *p = (const void*)req->data.args[0];
                int flags = (int)req->data.args[1];
                int mode  = (int)req->data.args[2];
                char path[256]={0}, fbuf[256];
                read_remote_string(tpid, p, path, sizeof(path));
                flags_to_str_open(flags, fbuf, sizeof fbuf);
                fprintf(stderr,
                    "{\"type\":\"policy.alert\",\"reason\":\"errno\",\"category\":\"fs\",\"syscall\":\"open\",\"syscall_no\":%d,"
                    "\"ts\":\"%s\",\"path\":\"%s\",\"flags\":\"%s\",\"mode\":%d,\"denied\":\"EPERM\"}\n",
                    scno, ts, path, fbuf, mode);
            }
#endif
            else if (scno == __NR_unlinkat) {
                const void *p = (const void*)req->data.args[1];
                int flags = (int)req->data.args[2];
                char path[256]={0};
                read_remote_string(tpid, p, path, sizeof(path));
                fprintf(stderr,
                    "{\"type\":\"policy.alert\",\"reason\":\"errno\",\"category\":\"fs\",\"syscall\":\"unlinkat\",\"syscall_no\":%d,"
                    "\"ts\":\"%s\",\"path\":\"%s\",\"flags\":%d,\"denied\":\"EPERM\"}\n", scno, ts, path, flags);
            }
#ifdef __NR_renameat2
            else if (scno == __NR_renameat2) {
                const void *op = (const void*)req->data.args[1];
                const void *np = (const void*)req->data.args[3];
                int flags = (int)req->data.args[4];
                char o[256]={0}, n[256]={0};
                read_remote_string(tpid, op, o, sizeof(o));
                read_remote_string(tpid, np, n, sizeof(n));
                fprintf(stderr,
                    "{\"type\":\"policy.alert\",\"reason\":\"errno\",\"category\":\"fs\",\"syscall\":\"renameat2\",\"syscall_no\":%d,"
                    "\"ts\":\"%s\",\"old\":\"%s\",\"new\":\"%s\",\"flags\":%d,\"denied\":\"EPERM\"}\n",
                    scno, ts, o, n, flags);
            }
#endif
            fflush(stderr);
            resp->id = req->id; resp->error = -EPERM; resp->val = 0; resp->flags = 0;
            if (seccomp_notify_respond(nfd, resp) != 0) break;
            continue;
        }

        /* Default: deny */
        resp->id = req->id; resp->error = -EPERM; resp->val = 0; resp->flags = 0;
        if (seccomp_notify_respond(nfd, resp) != 0) break;
    }

    seccomp_notify_free(req, resp); return NULL;
}

/* ---------- policy ---------- */
static scmp_filter_ctx
install_seccomp_filter(viol_mode_t vmode, bool diagnose)
{
    const bool trap_writes = (vmode == VMODE_TRAP);
    scmp_filter_ctx ctx = seccomp_init(diagnose ? SCMP_ACT_LOG : SCMP_ACT_TRAP);
    if (!ctx) die("seccomp_init failed");
    seccomp_attr_set(ctx, SCMP_FLTATR_CTL_LOG, 1);

    allow_common_dynbin(ctx);

    /* allow notifier fd handoff if needed */
    if (g_notify_exec || g_log_errno_fs) {
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
    }

    /* ===== Filesystem policy ===== */
    unsigned action_write = SCMP_ACT_TRAP;
    unsigned action_open_ro_allow = SCMP_ACT_ALLOW;

    if (g_allow_fs_write) {
        /* If filesystem write is explicitly allowed, permit everything */
        action_write = SCMP_ACT_ALLOW;
    } else if (g_log_errno_fs) {
        action_write = SCMP_ACT_NOTIFY;
    } else if (!trap_writes) {
        action_write = SCMP_ACT_ERRNO(EPERM);
    }

    /* openat/open: write/create/trim/tmpfile -> action_write */
    seccomp_rule_add(ctx, action_write, SCMP_SYS(openat), 1,
        SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_ACCMODE, O_WRONLY));
    seccomp_rule_add(ctx, action_write, SCMP_SYS(openat), 1,
        SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDWR));
    seccomp_rule_add(ctx, action_write, SCMP_SYS(openat), 1,
        SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_CREAT, O_CREAT));
    seccomp_rule_add(ctx, action_write, SCMP_SYS(openat), 1,
        SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_TRUNC, O_TRUNC));
#ifdef O_TMPFILE
    seccomp_rule_add(ctx, action_write, SCMP_SYS(openat), 1,
        SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_TMPFILE, O_TMPFILE));
#endif
#ifdef __NR_openat2
    seccomp_rule_add(ctx, action_write, SCMP_SYS(openat2), 0);
#endif
#ifdef __NR_open
    seccomp_rule_add(ctx, action_write, SCMP_SYS(open), 1,
        SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_ACCMODE, O_WRONLY));
    seccomp_rule_add(ctx, action_write, SCMP_SYS(open), 1,
        SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDWR));
    seccomp_rule_add(ctx, action_write, SCMP_SYS(open), 1,
        SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_CREAT, O_CREAT));
    seccomp_rule_add(ctx, action_write, SCMP_SYS(open), 1,
        SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_TRUNC, O_TRUNC));
#ifdef O_TMPFILE
    seccomp_rule_add(ctx, action_write, SCMP_SYS(open), 1,
        SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_TMPFILE, O_TMPFILE));
#endif
#endif
#ifdef __NR_creat
    seccomp_rule_add(ctx, action_write, SCMP_SYS(creat), 0);
#endif

    /* read-only open allowed */
    seccomp_rule_add(ctx, action_open_ro_allow, SCMP_SYS(openat), 2,
        SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDONLY),
        SCMP_CMP(2, SCMP_CMP_MASKED_EQ, (O_CREAT|O_TRUNC
#ifdef O_TMPFILE
                                         |O_TMPFILE
#endif
                                         ), 0));
#ifdef __NR_open
    seccomp_rule_add(ctx, action_open_ro_allow, SCMP_SYS(open), 2,
        SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDONLY),
        SCMP_CMP(1, SCMP_CMP_MASKED_EQ, (O_CREAT|O_TRUNC
#ifdef O_TMPFILE
                                         |O_TMPFILE
#endif
                                         ), 0));
#endif

    /* destructive metadata */
    unsigned action_meta = g_allow_fs_write ? SCMP_ACT_ALLOW :
                          (g_log_errno_fs ? SCMP_ACT_NOTIFY
                        : (trap_writes ? SCMP_ACT_TRAP : SCMP_ACT_ERRNO(EPERM)));
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(unlink), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(unlinkat), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(rename), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(renameat), 0);
#ifdef __NR_renameat2
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(renameat2), 0);
#endif
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(link), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(linkat), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(symlink), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(symlinkat), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(truncate), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(ftruncate), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(chmod), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(fchmod), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(fchmodat), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(chown), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(lchown), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(fchownat), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(utimensat), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(mkdir), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(mkdirat), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(rmdir), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(mknod), 0);
    seccomp_rule_add(ctx, action_meta, SCMP_SYS(mknodat), 0);

    /* ===== Networking ===== */
    unsigned action_net = g_allow_network ? SCMP_ACT_ALLOW : SCMP_ACT_TRAP;
    seccomp_rule_add(ctx, action_net, SCMP_SYS(socket), 0);
    seccomp_rule_add(ctx, action_net, SCMP_SYS(connect), 0);
    seccomp_rule_add(ctx, action_net, SCMP_SYS(accept), 0);
    seccomp_rule_add(ctx, action_net, SCMP_SYS(sendto), 0);
    seccomp_rule_add(ctx, action_net, SCMP_SYS(recvfrom), 0);
    seccomp_rule_add(ctx, action_net, SCMP_SYS(bind), 0);
    seccomp_rule_add(ctx, action_net, SCMP_SYS(listen), 0);

    /* ===== Exec ===== */
    if (g_notify_exec) {
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(execve), 0);
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(execveat), 0);
    } else {
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execveat), 0);
    }

    if (seccomp_load(ctx) != 0) die("seccomp_load failed");
    return ctx;
}

/* ---------- CLI ---------- */
static void usage(const char *p) {
    fprintf(stderr,
      "Usage: %s [OPTIONS] -- <program> [args...]\n"
      "Options:\n"
      "  --pidns           Enable PID namespace isolation\n"
      "  --mode=MODE       Violation mode: trap (kill) or errno (return error)\n"
      "  --log-continue    Continue execution after trap (log only)\n"
      "  --diagnose        Diagnostic mode (relaxed limits)\n"
      "  --notify-exec     Log process spawns via notify\n"
      "  --log-errno       Log filesystem operations with NOTIFY\n"
      "  --allow-fs-write  Allow filesystem write operations\n"
      "  --allow-network   Allow network operations\n", p);
    exit(2);
}

int main(int argc, char **argv) {
    bool pidns=false, diagnose=false;
    viol_mode_t vmode = VMODE_TRAP;

    int i=1;
    for (; i<argc; ++i) {
        if (!strcmp(argv[i],"--pidns")) pidns=true;
        else if (!strncmp(argv[i],"--mode=",7)) vmode = (!strcmp(argv[i]+7,"errno")? VMODE_ERRNO : VMODE_TRAP);
        else if (!strcmp(argv[i],"--log-continue")) g_continue_on_trap=1;
        else if (!strcmp(argv[i],"--diagnose")) diagnose=true;
        else if (!strcmp(argv[i],"--notify-exec")) g_notify_exec=true;
        else if (!strcmp(argv[i],"--log-errno")) g_log_errno_fs=true;
        else if (!strcmp(argv[i],"--allow-fs-write")) g_allow_fs_write=true;
        else if (!strcmp(argv[i],"--allow-network")) g_allow_network=true;
        else if (!strcmp(argv[i],"--")) { ++i; break; }
        else break;
    }
    if (i>=argc) usage(argv[0]);
    char **target = &argv[i];

    if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0)
        die("prctl(PR_SET_NO_NEW_PRIVS): %s", strerror(errno));

    maybe_unshare_pidns(pidns);
    set_limits(diagnose);

    int sv[2] = {-1,-1};
    const int need_notify_sock = (g_notify_exec || g_log_errno_fs);
    if (need_notify_sock && socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)!=0) die("socketpair");

    pid_t pid=fork(); if (pid<0) die("fork");
    if (pid==0) {
        if (need_notify_sock) close(sv[0]);

        struct sigaction sa; memset(&sa,0,sizeof(sa));
        sa.sa_sigaction = sigsys_handler; sa.sa_flags = SA_SIGINFO;
        if (sigaction(SIGSYS,&sa,NULL)!=0) die("sigaction(SIGSYS): %s", strerror(errno));

        scmp_filter_ctx ctx = install_seccomp_filter(vmode, diagnose);

        if (need_notify_sock) {
            int nfd = seccomp_notify_fd(ctx);
            if (nfd < 0) die("seccomp_notify_fd");
            if (send_fd(sv[1], nfd) < 0) die("send_fd");
            close(nfd); close(sv[1]);
        }

        execvp(target[0], target);
        perror("execvp");
        _exit(127);
    }

    pthread_t th = 0;
    if (need_notify_sock) {
        close(sv[1]);
        int nfd = recv_fd(sv[0]); close(sv[0]);
        if (nfd >= 0) pthread_create(&th, NULL, supervisor_thread, (void*)(intptr_t)nfd);
    }

    int status=0; if (waitpid(pid,&status,0)<0) die("waitpid");
    if (need_notify_sock && th) { pthread_cancel(th); pthread_join(th, NULL); }

    if (WIFEXITED(status)) { 
        fprintf(stderr,"[sandbox] child exited %d\n", WEXITSTATUS(status)); 
        return WEXITSTATUS(status); 
    }
    if (WIFSIGNALED(status)) { 
        fprintf(stderr,"[sandbox] child killed by signal %d\n", WTERMSIG(status)); 
        return 128+WTERMSIG(status); 
    }
    return 1;
}