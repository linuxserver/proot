/*
 * stopcost: the floor cost of intercepting one syscall, three ways.
 *
 *   none       plain syscall, no filter
 *   ptrace     seccomp SECCOMP_RET_TRACE + tracer doing GETREGS/CONT
 *              (what PRoot does for every traced syscall at sysenter)
 *   ptrace2    same, plus a PTRACE_SYSCALL exit stop (PRoot's
 *              FILTER_SYSEXIT syscalls: ioctl, statx, readlink, ...)
 *   usernotif  seccomp SECCOMP_RET_USER_NOTIF answered by a supervisor
 *              thread (no ptrace stop, no scheduler hop through the
 *              tracer's wait loop)
 *
 *   gcc -O2 -pthread -o stopcost stopcost.c && ./stopcost
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_EVENT_SECCOMP
#define PTRACE_EVENT_SECCOMP 7
#endif
#ifndef PTRACE_O_TRACESECCOMP
#define PTRACE_O_TRACESECCOMP 0x80
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_RECV
struct seccomp_notif {
	__u64 id; __u32 pid; __u32 flags; struct seccomp_data data;
};
struct seccomp_notif_resp {
	__u64 id; __s64 val; __s32 error; __u32 flags;
};
#define SECCOMP_IOC_MAGIC '!'
#define SECCOMP_IOCTL_NOTIF_RECV _IOWR(SECCOMP_IOC_MAGIC, 0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND _IOWR(SECCOMP_IOC_MAGIC, 1, struct seccomp_notif_resp)
#endif

#if defined(__x86_64__)
#define ARCH_NR AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define ARCH_NR AUDIT_ARCH_AARCH64
#else
#error "add your arch"
#endif

static long N = 200000;
#define PROBE_NR SYS_getppid

static double now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static int install_filter(uint32_t action, unsigned long flags)
{
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH_NR, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROBE_NR, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, action),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = { .len = sizeof(f) / sizeof(f[0]), .filter = f };
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		return -1;
	return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &prog);
}

static void child_loop(void)
{
	for (long i = 0; i < N; i++)
		syscall(PROBE_NR);
	_exit(0);
}

static void run_none(void)
{
	double t0 = now_ns();
	pid_t p = fork();
	if (p == 0)
		child_loop();
	waitpid(p, NULL, 0);
	printf("%-12s %8.0f ns/op\n", "none", (now_ns() - t0) / N);
}

static void run_ptrace(int with_exit)
{
	pid_t p = fork();
	if (p == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		raise(SIGSTOP);
		if (install_filter(SECCOMP_RET_TRACE, 0) < 0) {
			perror("seccomp"); _exit(1);
		}
		child_loop();
	}
	int status;
	waitpid(p, &status, 0);
	ptrace(PTRACE_SETOPTIONS, p, NULL, PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL);
	double t0 = now_ns();
	ptrace(PTRACE_CONT, p, NULL, NULL);
	for (;;) {
		waitpid(p, &status, 0);
		if (WIFEXITED(status))
			break;
		if (WIFSTOPPED(status)) {
			int ev = status >> 16;
			if (ev == PTRACE_EVENT_SECCOMP) {
				struct user_regs_struct regs;
				ptrace(PTRACE_GETREGS, p, NULL, &regs);
				/* PRoot reads a path from the tracee here; a GETREGS
				 * is the cheapest stand-in for "look at the args". */
				if (with_exit) {
					ptrace(PTRACE_SYSCALL, p, NULL, NULL);
					waitpid(p, &status, 0);	/* exit stop */
					ptrace(PTRACE_GETREGS, p, NULL, &regs);
				}
			}
			ptrace(PTRACE_CONT, p, NULL, NULL);
		}
	}
	printf("%-12s %8.0f ns/op\n", with_exit ? "ptrace2" : "ptrace", (now_ns() - t0) / N);
}

struct sup_arg { int fd; };
static void *supervisor(void *arg)
{
	int fd = ((struct sup_arg *) arg)->fd;
	struct seccomp_notif req;
	struct seccomp_notif_resp resp;
	for (;;) {
		memset(&req, 0, sizeof(req));
		if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		memset(&resp, 0, sizeof(resp));
		resp.id = req.id;
		resp.val = 1;	/* emulate: answer the syscall ourselves */
		ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
	}
	return NULL;
}

static void run_usernotif(void)
{
	int sv[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	pid_t p = fork();
	if (p == 0) {
		close(sv[0]);
		int lfd = install_filter(SECCOMP_RET_USER_NOTIF, SECCOMP_FILTER_FLAG_NEW_LISTENER);
		if (lfd < 0) {
			perror("seccomp user_notif"); _exit(1);
		}
		/* hand the listener to the parent */
		char c = 0;
		struct iovec iov = { &c, 1 };
		char cbuf[CMSG_SPACE(sizeof(int))];
		struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
		struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
		cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_RIGHTS; cm->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cm), &lfd, sizeof(int));
		sendmsg(sv[1], &mh, 0);
		read(sv[1], &c, 1);	/* wait for go */
		child_loop();
	}
	close(sv[1]);
	char c;
	struct iovec iov = { &c, 1 };
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
	if (recvmsg(sv[0], &mh, 0) <= 0) {
		printf("%-12s unavailable (kernel < 5.0 or seccomp blocked)\n", "usernotif");
		waitpid(p, NULL, 0);
		return;
	}
	int lfd;
	memcpy(&lfd, CMSG_DATA(CMSG_FIRSTHDR(&mh)), sizeof(int));
	struct sup_arg sa = { lfd };
	pthread_t th;
	pthread_create(&th, NULL, supervisor, &sa);
	double t0 = now_ns();
	write(sv[0], &c, 1);
	waitpid(p, NULL, 0);
	printf("%-12s %8.0f ns/op\n", "usernotif", (now_ns() - t0) / N);
	close(lfd);
}

int main(int argc, char **argv)
{
	if (argc > 1)
		N = atol(argv[1]);
	printf("# stopcost: %ld probe syscalls per mode\n", N);
	run_none();
	run_ptrace(0);
	run_ptrace(1);
	run_usernotif();
	return 0;
}
