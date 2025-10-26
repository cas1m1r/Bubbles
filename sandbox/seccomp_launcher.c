/* seccomp_launcher.c  -- add --trace-net and --peek-tx
   Build: cc -O2 -Wall -Wextra -o seccomp_launcher seccomp_launcher.c -lseccomp -lpthread
   Run:   ./seccomp_launcher [--pidns] [--deny-fs=1|0] [--deny-net=1|0] [--trace-net[=1|0]] [--peek-tx=N]
                       [--notify-exec] [--diagnose] -- <program> [args...]
*/

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

/* ----------------- globals / knobs ----------------- */
static int g_deny_fs     = 1;  // deny filesystem mutations (via NOTIFY)
static int g_deny_net    = 1;  // deny networking (via NOTIFY)
static int g_notify_exec = 0;  // log & allow exec via NOTIFY
static int g_diagnose    = 0;  // ask kernel to LOG filter matches
static int g_trace_net   = 0;  // observe network syscalls even when allowed
static int g_peek_tx_bytes = 0; // if >0, peek up to N bytes from sendto/sendmsg buffers

/* supervisor NOTIFY fd (so parent can stop thread) */
static int g_notify_fd = -1;

/* ----------------- small utils ----------------- */
static void jlog(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
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

/* ----------------- remote memory helpers (best-effort) ----------------- */
static ssize_t read_remote(pid_t pid, const void *remote_ptr, void *local_buf, size_t len) {
    if (!remote_ptr || !local_buf || len == 0) return -1;
    struct iovec liov = { .iov_base = local_buf, .iov_len = len };
    struct iovec riov = { .iov_base = (void*)remote_ptr, .iov_len = len };
    ssize_t n = syscall(SYS_process_vm_readv, (pid_t)pid, &liov, 1, &riov, 1, 0);
    if (n < 0) return -1;
    return n;
}
static void read_remote_string(pid_t pid, const void *remote_ptr, char *out, size_t cap) {
    if (!out || cap == 0) return;
    out[0]='\0';
    if (!remote_ptr) return;
    ssize_t r = read_remote(pid, remote_ptr, out, cap-1);
    if (r <= 0) { snprintf(out, cap, "<unreadable>"); return; }
    out[r] = '\0';
    for (size_t i = 0; i < (size_t)r; ++i) if (out[i] == '\0') return;
    out[r] = '\0';
}
static void hexify(const unsigned char *in, size_t n, char *out, size_t outcap) {
    static const char *H="0123456789abcdef"; size_t j=0;
    for (size_t i=0;i<n && j+2<outcap;i++){ out[j++]=H[in[i]>>4]; out[j++]=H[in[i]&15]; }
    if (j<outcap) out[j]='\0';
}

/* deny-mode connect logger (kept for compatibility) */
static void log_connect_deny(int scno, pid_t tpid, const void *saptr, socklen_t slen) {
    char peer[128]={0}; int port=-1; int fam=-1; unsigned char buf[256];
    size_t n=(size_t)slen; if (n>sizeof(buf)) n=sizeof(buf);
    if (saptr && n>0 && read_remote(tpid, saptr, buf, n)==(ssize_t)n) {
        const struct sockaddr *sa=(const struct sockaddr*)buf; fam=sa->sa_family;
        if (fam==AF_INET && n>=sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *in=(const struct sockaddr_in*)sa;
            inet_ntop(AF_INET,&in->sin_addr,peer,sizeof(peer)); port=ntohs(in->sin_port);
        } else if (fam==AF_INET6 && n>=sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *in6=(const struct sockaddr_in6*)sa;
            inet_ntop(AF_INET6,&in6->sin6_addr,peer,sizeof(peer)); port=ntohs(in6->sin6_port);
        } else if (fam==AF_UNIX) snprintf(peer,sizeof(peer),"unix");
        else snprintf(peer,sizeof(peer),"family=%d",fam);
    } else snprintf(peer,sizeof(peer),"<unreadable>");
    char ts[64]; timestr(ts);
    jlog("{\"type\":\"policy.alert\",\"reason\":\"errno\",\"category\":\"net\",\"syscall\":\"connect\","
         "\"syscall_no\":%d,\"ts\":\"%s\",\"peer\":\"%s\",\"port\":%d,\"family\":%d,\"denied\":\"EPERM\"}",
         scno, ts, peer, port, fam);
}
/* allow-mode connect logger (neutral) */
static void log_connect_allow(int scno, pid_t tpid, const void *saptr, socklen_t slen) {
    char peer[128]={0}; int port=-1; int fam=-1; unsigned char buf[256];
    size_t n=(size_t)slen; if (n>sizeof(buf)) n=sizeof(buf);
    if (saptr && n>0 && read_remote(tpid, saptr, buf, n)==(ssize_t)n) {
        const struct sockaddr *sa=(const struct sockaddr*)buf; fam=sa->sa_family;
        if (fam==AF_INET && n>=sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *in=(const struct sockaddr_in*)sa;
            inet_ntop(AF_INET,&in->sin_addr,peer,sizeof(peer)); port=ntohs(in->sin_port);
        } else if (fam==AF_INET6 && n>=sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *in6=(const struct sockaddr_in6*)sa;
            inet_ntop(AF_INET6,&in6->sin6_addr,peer,sizeof(peer)); port=ntohs(in6->sin6_port);
        } else if (fam==AF_UNIX) snprintf(peer,sizeof(peer),"unix");
        else snprintf(peer,sizeof(peer),"family=%d",fam);
    } else snprintf(peer,sizeof(peer),"<unreadable>");
    char ts[64]; timestr(ts);
    jlog("{\"type\":\"net.connect\",\"syscall\":\"connect\",\"syscall_no\":%d,\"ts\":\"%s\","
         "\"peer\":\"%s\",\"port\":%d,\"family\":%d,\"decision\":\"ALLOW\"}",
         scno, ts, peer, port, fam);
}

/* ----------------- allowlist builder ----------------- */
static void allow_common(scmp_filter_ctx ctx) {
    /* lifecycle/signals */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigaltstack), 0);

    /* stdio / fcntl */
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

    /* memory/time/threads */
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

    /* ids/env/infos */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);

    /* read-only fs */
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

    /* proc control */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(waitid), 0);

    /* timers */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setitimer), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);

    /* NOTE: do NOT blanket-ALLOW sendmsg/recvmsg here, so that NOTIFY rules added later can trigger */
}

/* ---------- install filter (returns ctx already loaded) ---------- */
static scmp_filter_ctx install_filter(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) { perror("seccomp_init"); exit(1); }

    if (g_diagnose) seccomp_attr_set(ctx, SCMP_FLTATR_CTL_LOG, 1);

    allow_common(ctx);

    /* FS mutations -> NOTIFY if requested */
    if (g_deny_fs) {
#ifdef __NR_openat
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 1,
            SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_ACCMODE, O_WRONLY));
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 1,
            SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDWR));
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 1,
            SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_CREAT, O_CREAT));
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 1,
            SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_TRUNC, O_TRUNC));
#endif
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

    /* Networking -> NOTIFY if deny OR tracing enabled */
    if (g_deny_net || g_trace_net) {
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(socket), 0);
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(connect), 0);
        if (g_peek_tx_bytes > 0) {
#ifdef __NR_sendto
            seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(sendto), 0);
#endif
#ifdef __NR_sendmsg
            seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(sendmsg), 0);
#endif
        }
    }

    /* Exec: either NOTIFY (log) or plain allow */
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

/* ----------------- fd passing helpers ----------------- */
static int send_fd(int sock, int fd) {
    struct msghdr msg = {0};
    struct iovec iov; char buf[1]={0};
    iov.iov_base=buf; iov.iov_len=1;
    msg.msg_iov=&iov; msg.msg_iovlen=1;

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    msg.msg_control=cmsgbuf; msg.msg_controllen=sizeof(cmsgbuf);
    struct cmsghdr *cmsg=CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len=CMSG_LEN(sizeof(int));
    cmsg->cmsg_level=SOL_SOCKET; cmsg->cmsg_type=SCM_RIGHTS;
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
    if (sendmsg(sock, &msg, 0) <= 0) return -1;
    return 0;
}
static int recv_fd_nonblock(int sock, int timeout_ms) {
    struct pollfd pfd={ .fd=sock, .events=POLLIN };
    int rv=poll(&pfd,1,timeout_ms);
    if (rv<=0) return -1;
    struct msghdr msg={0};
    struct iovec iov; char buf[1];
    iov.iov_base=buf; iov.iov_len=1;
    msg.msg_iov=&iov; msg.msg_iovlen=1;
    char cmsgbuf[256];
    msg.msg_control=cmsgbuf; msg.msg_controllen=sizeof(cmsgbuf);
    ssize_t n=recvmsg(sock,&msg,0);
    if (n<=0) return -1;
    struct cmsghdr *cmsg=CMSG_FIRSTHDR(&msg);
    if (!cmsg) return -1;
    if (cmsg->cmsg_level==SOL_SOCKET && cmsg->cmsg_type==SCM_RIGHTS) {
        int fd; memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
        return fd;
    }
    return -1;
}

/* ----------------- supervisor thread (seccomp notify loop) ----------------- */
static void *supervisor_thread(void *arg) {
    int nfd = (int)(intptr_t)arg; g_notify_fd = nfd;

    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;
    if (seccomp_notify_alloc(&req, &resp) != 0) return NULL;

    /* Optional external JSON supervisor (env SUPERVISOR_JSON_FD) */
    int sup_fd = -1;
    const char *supfd_env = getenv("SUPERVISOR_JSON_FD");
    if (supfd_env) { sup_fd = atoi(supfd_env); if (sup_fd < 0) sup_fd = -1; }

    for (;;) {
        if (seccomp_notify_receive(nfd, req) != 0) break;

        int scno = req->data.nr;
        pid_t tpid = req->pid;
        const char *sname = sys_name(scno);

        /* Forward to external supervisor if present */
        if (sup_fd >= 0) {
            char outbuf[2048], inbuf[512]; int outlen=0;
            snprintf(outbuf, sizeof(outbuf),
                "{\"type\":\"notify\",\"syscall\":\"%s\",\"syscall_no\":%d,\"pid\":%d",
                sname, scno, tpid);
            outlen = (int)strlen(outbuf);

            if (scno == __NR_openat || scno == __NR_open) {
                char path[256]={0};
                const void *pathptr = (scno==__NR_openat) ? (const void*)req->data.args[1] : (const void*)req->data.args[0];
                read_remote_string(tpid, pathptr, path, sizeof(path));
                int flags = (int)((scno==__NR_openat)?req->data.args[2]:req->data.args[1]);
                int mode  = (int)((scno==__NR_openat)?req->data.args[3]:req->data.args[2]);
                outlen += snprintf(outbuf+outlen, sizeof(outbuf)-outlen, ",\"path\":\"%s\",\"flags\":%d,\"mode\":%d", path, flags, mode);
            } else if (scno == __NR_connect) {
                char peer[128]={0}; int port=-1;
                unsigned char buf[128]; size_t n=(size_t)req->data.args[2]; if (n>sizeof(buf)) n=sizeof(buf);
                if (req->data.args[1] && read_remote(tpid,(const void*)req->data.args[1],buf,n)==(ssize_t)n) {
                    const struct sockaddr *sa=(const struct sockaddr*)buf;
                    if (sa->sa_family==AF_INET && n>=sizeof(struct sockaddr_in)) {
                        const struct sockaddr_in *in=(const struct sockaddr_in*)sa;
                        inet_ntop(AF_INET,&in->sin_addr,peer,sizeof(peer));
                        port=ntohs(in->sin_port);
                    }
                }
                outlen += snprintf(outbuf+outlen, sizeof(outbuf)-outlen, ",\"peer\":\"%s\",\"port\":%d", peer[0]?peer:"<unk>", port);
            } else if (scno == __NR_unlinkat) {
                char path[256]={0};
                read_remote_string(tpid,(const void*)req->data.args[1],path,sizeof(path));
                outlen += snprintf(outbuf+outlen, sizeof(outbuf)-outlen, ",\"path\":\"%s\"", path);
            }
            outlen += snprintf(outbuf+outlen, sizeof(outbuf)-outlen, "}\n");

            if (write(sup_fd, outbuf, outlen) <= 0) {
                resp->id=req->id; resp->error=-EPERM; resp->val=0; resp->flags=0;
                seccomp_notify_respond(nfd, resp); continue;
            }
            ssize_t r = read(sup_fd, inbuf, sizeof(inbuf)-1);
            if (r <= 0) {
                resp->id=req->id; resp->error=-EPERM; resp->val=0; resp->flags=0;
                seccomp_notify_respond(nfd, resp); continue;
            }
            inbuf[r]='\0';
            if (strstr(inbuf,"\"action\":\"ALLOW\"")) {
                resp->id=req->id; resp->error=0; resp->val=0; resp->flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                seccomp_notify_respond(nfd, resp); continue;
            } else if (strstr(inbuf,"\"action\":\"DENY_ERRNO\"")) {
                int err=EPERM; char *p=strstr(inbuf,"\"errno\":"); if (p) err=atoi(p+8);
                resp->id=req->id; resp->error=-err; resp->val=0; resp->flags=0;
                seccomp_notify_respond(nfd, resp); continue;
            } else if (strstr(inbuf,"\"action\":\"EMULATE_RET\"")) {
                int retv=0; char *p=strstr(inbuf,"\"ret\":"); if (p) retv=atoi(p+6);
                resp->id=req->id; resp->error=0; resp->val=retv; resp->flags=0;
                seccomp_notify_respond(nfd, resp); continue;
            } else if (strstr(inbuf,"\"action\":\"QUARANTINE\"")) {
                resp->id=req->id; resp->error=-EPERM; resp->val=0; resp->flags=0;
                seccomp_notify_respond(nfd, resp);
                char ts[64]; timestr(ts);
                jlog("{\"type\":\"policy.alert\",\"reason\":\"quarantine\",\"syscall\":\"%s\",\"syscall_no\":%d,\"pid\":%d,\"ts\":\"%s\"}",
                     sname, scno, tpid, ts);
                continue;
            } else {
                resp->id=req->id; resp->error=-EPERM; resp->val=0; resp->flags=0;
                seccomp_notify_respond(nfd, resp); continue;
            }
        }

        /* exec: log & allow when requested */
        if (g_notify_exec && (scno == __NR_execve || scno == __NR_execveat)) {
            char path[256]={0}; char ts[64];
            const void *p=(const void*)req->data.args[0];
            read_remote_string(tpid, p, path, sizeof(path));
            timestr(ts);
            jlog("{\"type\":\"process.spawn\",\"syscall\":\"%s\",\"pid\":%d,\"exe\":\"%s\",\"ts\":\"%s\"}",
                 sys_name(scno), tpid, path[0]?path:"<unknown>", ts);
            resp->id=req->id; resp->error=0; resp->val=0; resp->flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            seccomp_notify_respond(nfd, resp); continue;
        }

        /* trace: log allowed socket/connect */
        if ((scno == __NR_socket || scno == __NR_connect) && g_trace_net && !g_deny_net) {
            if (scno == __NR_socket) {
                int dom=(int)req->data.args[0], type=(int)req->data.args[1], proto=(int)req->data.args[2];
                char ts[64]; timestr(ts);
                jlog("{\"type\":\"net.socket\",\"syscall\":\"socket\",\"syscall_no\":%d,\"ts\":\"%s\","
                     "\"domain\":%d,\"type\":%d,\"proto\":%d,\"decision\":\"ALLOW\"}",
                     scno, ts, dom, type, proto);
            } else {
                log_connect_allow(scno, tpid, (const void*)req->data.args[1], (socklen_t)req->data.args[2]);
            }
            resp->id=req->id; resp->error=0; resp->val=0; resp->flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            seccomp_notify_respond(nfd, resp); continue;
        }

        /* payload preview for sendto/sendmsg (only when tracing & allowed) */
        if (g_peek_tx_bytes > 0 && g_trace_net && !g_deny_net &&
            (scno == __NR_sendto || scno == __NR_sendmsg)) {
            char hex[1024]={0}; size_t want=(size_t)g_peek_tx_bytes;
            if (scno == __NR_sendto) {
                const void *bufptr=(const void*)req->data.args[0];
                size_t len=(size_t)req->data.args[1];
                size_t n=len<want?len:want; if (n>512) n=512;
                unsigned char tmp[512];
                if (bufptr && read_remote(tpid, bufptr, tmp, n) == (ssize_t)n) {
                    hexify(tmp, n, hex, sizeof(hex));
                    char ts[64]; timestr(ts);
                    jlog("{\"type\":\"net.tx.peek\",\"syscall\":\"sendto\",\"bytes\":%zu,\"hex\":\"%s\",\"ts\":\"%s\",\"decision\":\"ALLOW\"}", n, hex, ts);
                } else {
                    char ts[64]; timestr(ts);
                    jlog("{\"type\":\"net.tx.peek\",\"syscall\":\"sendto\",\"bytes\":0,\"hex\":\"<unreadable>\",\"ts\":\"%s\",\"decision\":\"ALLOW\"}", ts);
                }
            } else { /* sendmsg */
                struct msghdr mhdr;
                if (read_remote(tpid, (const void*)req->data.args[1], &mhdr, sizeof(mhdr)) == (ssize_t)sizeof(mhdr)) {
                    struct iovec iov0;
                    if (mhdr.msg_iov &&
                        read_remote(tpid, mhdr.msg_iov, &iov0, sizeof(iov0)) == (ssize_t)sizeof(iov0) &&
                        iov0.iov_base && iov0.iov_len) {
                        size_t n=iov0.iov_len < want ? iov0.iov_len : want; if (n>512) n=512;
                        unsigned char tmp[512];
                        if (read_remote(tpid, iov0.iov_base, tmp, n) == (ssize_t)n) {
                            hexify(tmp, n, hex, sizeof(hex));
                            char ts[64]; timestr(ts);
                            jlog("{\"type\":\"net.tx.peek\",\"syscall\":\"sendmsg\",\"bytes\":%zu,\"hex\":\"%s\",\"ts\":\"%s\",\"decision\":\"ALLOW\"}", n, hex, ts);
                        }
                    }
                }
            }
            resp->id=req->id; resp->error=0; resp->val=0; resp->flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            seccomp_notify_respond(nfd, resp); continue;
        }

        /* FS denials (log, then EPERM) */
        if (g_deny_fs) {
            if (scno == __NR_openat) {
                char path[256]={0};
                read_remote_string(tpid, (const void*)req->data.args[1], path, sizeof(path));
                int flags=(int)req->data.args[2]; int mode=(int)req->data.args[3];
                char ts[64]; timestr(ts);
                jlog("{\"type\":\"policy.alert\",\"reason\":\"errno\",\"category\":\"fs\",\"syscall\":\"openat\","
                     "\"syscall_no\":%d,\"ts\":\"%s\",\"path\":\"%s\",\"flags\":%d,\"mode\":%d,\"denied\":\"EPERM\"}",
                     scno, ts, path, flags, mode);
                goto deny;
            }
#ifdef __NR_open
            if (scno == __NR_open) {
                char path[256]={0};
                read_remote_string(tpid, (const void*)req->data.args[0], path, sizeof(path));
                int flags=(int)req->data.args[1]; int mode=(int)req->data.args[2];
                char ts[64]; timestr(ts);
                jlog("{\"type\":\"policy.alert\",\"reason\":\"errno\",\"category\":\"fs\",\"syscall\":\"open\","
                     "\"syscall_no\":%d,\"ts\":\"%s\",\"path\":\"%s\",\"flags\":%d,\"mode\":%d,\"denied\":\"EPERM\"}",
                     scno, ts, path, flags, mode);
                goto deny;
            }
#endif
#ifdef __NR_unlinkat
            if (scno == __NR_unlinkat) {
                char path[256]={0}; read_remote_string(tpid,(const void*)req->data.args[1],path,sizeof(path));
                char ts[64]; timestr(ts);
                jlog("{\"type\":\"policy.alert\",\"reason\":\"errno\",\"category\":\"fs\",\"syscall\":\"unlinkat\","
                     "\"syscall_no\":%d,\"ts\":\"%s\",\"path\":\"%s\",\"denied\":\"EPERM\"}",
                     scno, ts, path);
                goto deny;
            }
#endif
        }

        /* NET denials (log, then EPERM) */
        if (g_deny_net) {
            if (scno == __NR_socket) {
                int dom=(int)req->data.args[0], type=(int)req->data.args[1], proto=(int)req->data.args[2];
                char ts[64]; timestr(ts);
                jlog("{\"type\":\"policy.alert\",\"reason\":\"errno\",\"category\":\"net\",\"syscall\":\"socket\","
                     "\"syscall_no\":%d,\"ts\":\"%s\",\"domain\":%d,\"type\":%d,\"proto\":%d,\"denied\":\"EPERM\"}",
                     scno, ts, dom, type, proto);
                goto deny;
            }
            if (scno == __NR_connect) {
                log_connect_deny(scno, tpid, (const void*)req->data.args[1], (socklen_t)req->data.args[2]);
                goto deny;
            }
            if (scno == __NR_sendto || scno == __NR_sendmsg) {
                char ts[64]; timestr(ts);
                jlog("{\"type\":\"policy.alert\",\"reason\":\"errno\",\"category\":\"net\",\"syscall\":\"%s\","
                     "\"syscall_no\":%d,\"ts\":\"%s\",\"denied\":\"EPERM\"}",
                     sys_name(scno), scno, ts);
                goto deny;
            }
        }

deny:
        /* default deny path */
        resp->id=req->id; resp->error=-EPERM; resp->val=0; resp->flags=0;
        if (seccomp_notify_respond(nfd, resp) != 0) break;
    }

    seccomp_notify_free(req, resp);
    return NULL;
}

/* ---------- namespaces & rlimits ---------- */
static void maybe_unshare_pidns(bool enabled) {
    if (enabled && unshare(CLONE_NEWPID) != 0) perror("unshare(CLONE_NEWPID)");
}
static void set_limits(void) {
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = 10; setrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = rl.rlim_max = 2*1024*1024*1024ULL; setrlimit(RLIMIT_AS, &rl);
}

/* ---------- CLI & main ---------- */
static void usage(const char *p) {
    fprintf(stderr,
      "Usage: %s [--pidns] [--deny-fs=1|0] [--deny-net=1|0] [--trace-net[=1|0]] [--peek-tx=N]\n"
      "       [--notify-exec] [--diagnose] -- <program> [args...]\n", p);
    exit(2);
}
static int parse_bool_opt(const char *s, int def1) { const char *eq=strchr(s,'='); return eq? (atoi(eq+1)?1:0) : def1; }

int main(int argc, char **argv) {
    bool pidns=false; int i=1;
    for (; i<argc; ++i) {
        const char *a=argv[i];
        if (!strcmp(a,"--")) { ++i; break; }
        else if (!strcmp(a,"--pidns")) pidns=true;
        else if (!strncmp(a,"--deny-fs",9))   g_deny_fs  = parse_bool_opt(a,1);
        else if (!strncmp(a,"--deny-net",10)) g_deny_net = parse_bool_opt(a,1);
        else if (!strncmp(a,"--trace-net",11)) g_trace_net = parse_bool_opt(a,1);
        else if (!strncmp(a,"--peek-tx",9)) { const char *eq=strchr(a,'='); g_peek_tx_bytes = eq? atoi(eq+1):0; }
        else if (!strcmp(a,"--notify-exec")) g_notify_exec=1;
        else if (!strcmp(a,"--diagnose")) g_diagnose=1;
        else { fprintf(stderr,"Unknown option: %s\n", a); usage(argv[0]); }
    }
    if (i>=argc) usage(argv[0]);
    char **target = &argv[i];

    if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0) { perror("prctl(PR_SET_NO_NEW_PRIVS)"); return 1; }

    maybe_unshare_pidns(pidns);
    set_limits();

    { char ts[64]; timestr(ts);
      jlog("{\"type\":\"process.spawn\",\"exe\":\"%s\",\"ts\":\"%s\"}", target[0], ts);
    }

    int need_notify = (g_deny_fs || g_deny_net || g_notify_exec || g_trace_net || (g_peek_tx_bytes>0));

    int sv[2] = {-1,-1};
    if (need_notify && socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)!=0) { perror("socketpair"); need_notify=0; }

    pid_t pid=fork();
    if (pid<0) { perror("fork"); return 1; }

    if (pid==0) {
		// child
		if (need_notify) close(sv[0]);

		scmp_filter_ctx ctx = install_filter();

		if (need_notify) {
			int nfd = seccomp_notify_fd(ctx);
			if (nfd < 0) { perror("seccomp_notify_fd"); close(sv[1]); _exit(127); }

			// send nfd to parent
			if (send_fd(sv[1], nfd) < 0) { perror("send_fd"); close(nfd); close(sv[1]); _exit(127); }
			// child no longer needs its copy; parent supervises
			close(nfd);

			// wait for parent's "ready" byte before exec so connect() won't block on a race
			char ack;
			if (read(sv[1], &ack, 1) != 1) { /* parent died? */ close(sv[1]); _exit(127); }
			close(sv[1]);
		} else {
			(void)install_filter();
		}

		execvp(target[0], target);
		perror("execvp");
		_exit(127);
	}


    // parent
	int nfd = -1; pthread_t th = 0;
	if (need_notify) {
		close(sv[1]);

		// receive notify fd from child
		nfd = recv_fd_nonblock(sv[0], 3000);
		if (nfd < 0) { fprintf(stderr,"[seccomp] failed to obtain notify fd from child\n"); close(sv[0]); }

		// start supervisor thread first...
		if (nfd >= 0) (void)pthread_create(&th, NULL, supervisor_thread, (void*)(intptr_t)nfd);

		// ...then signal child we’re ready so it can exec()
		char ack = 'R';
		(void)write(sv[0], &ack, 1);
		close(sv[0]);
	}


    int status=0;
    if (waitpid(pid,&status,0) < 0) perror("waitpid");

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
