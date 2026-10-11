/*
 * sysbench: a syscall-heavy micro benchmark for PRoot.
 *
 * Run it natively, then under proot, and compare the per-operation
 * cost of the syscalls a desktop application hammers: path lookups,
 * descriptor churn, ioctl, unix socket traffic, process creation,
 * and a few untraced controls to show the floor.
 *
 *   gcc -O2 -pthread -o sysbench sysbench.c
 *   ./sysbench                 # native
 *   proot ./sysbench           # traced
 *   ./sysbench -n 20000 -t 8   # tune iterations / threads
 *
 * Output is one line per test: name, ns per op, ops per second.
 * Each test is self-contained and runs in a temp directory.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long iterations = 10000;
static int nthreads = 4;
static char base[PATH_MAX];
static char deep_file[PATH_MAX];
static char link_path[PATH_MAX];
static int only_filter = 0;
static const char *only_name = NULL;

static double now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static void report(const char *name, double ns_total, long ops)
{
	double per = ns_total / ops;
	printf("%-28s %10.0f ns/op %12.0f ops/s\n", name, per, 1e9 / per);
	fflush(stdout);
}

static int wanted(const char *name)
{
	return !only_filter || strstr(name, only_name) != NULL;
}

#define BENCH(name, setup, body, teardown) do {			\
	if (!wanted(name)) break;					\
	setup;								\
	double t0 = now_ns();						\
	for (long i = 0; i < iterations; i++) { body; }		\
	double t1 = now_ns();						\
	teardown;							\
	report(name, t1 - t0, iterations);				\
} while (0)

static void die(const char *what)
{
	perror(what);
	exit(1);
}

static void setup_tree(void)
{
	const char *tmp = getenv("TMPDIR");
	char cur[PATH_MAX];
	int fd;

	if (tmp == NULL)
		tmp = "/tmp";
	snprintf(base, sizeof(base), "%s/sysbench.%d", tmp, (int) getpid());
	if (mkdir(base, 0700) < 0)
		die("mkdir base");
	strcpy(cur, base);
	for (int d = 0; d < 8; d++) {
		strcat(cur, "/dir");
		if (mkdir(cur, 0700) < 0)
			die("mkdir depth");
	}
	snprintf(deep_file, sizeof(deep_file), "%s/file", cur);
	fd = open(deep_file, O_WRONLY | O_CREAT, 0600);
	if (fd < 0)
		die("create deep file");
	write(fd, "x", 1);
	close(fd);
	snprintf(link_path, sizeof(link_path), "%s/link", base);
	if (symlink(deep_file, link_path) < 0)
		die("symlink");
}

static void teardown_tree(void)
{
	char cmd[PATH_MAX + 16];
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", base);
	system(cmd);
}

/* ---- threaded stat storm: shows tracer serialisation ---- */
static void *stat_worker(void *arg)
{
	long n = (long) arg;
	struct stat st;
	for (long i = 0; i < n; i++)
		stat(deep_file, &st);
	return NULL;
}

static void bench_threads(int t)
{
	char name[64];
	pthread_t th[64];
	snprintf(name, sizeof(name), "stat x%d threads", t);
	if (!wanted(name))
		return;
	double t0 = now_ns();
	for (int i = 0; i < t; i++)
		pthread_create(&th[i], NULL, stat_worker, (void *) iterations);
	for (int i = 0; i < t; i++)
		pthread_join(th[i], NULL);
	double t1 = now_ns();
	report(name, t1 - t0, iterations * t);
}

/* ---- process creation ---- */
static void bench_fork(void)
{
	long n = iterations / 50 > 0 ? iterations / 50 : 1;
	if (wanted("fork+wait")) {
		double t0 = now_ns();
		for (long i = 0; i < n; i++) {
			pid_t p = fork();
			if (p == 0)
				_exit(0);
			waitpid(p, NULL, 0);
		}
		report("fork+wait", now_ns() - t0, n);
	}
	if (wanted("fork+exec /bin/true")) {
		double t0 = now_ns();
		for (long i = 0; i < n; i++) {
			pid_t p = fork();
			if (p == 0) {
				execl("/bin/true", "true", (char *) NULL);
				_exit(127);
			}
			waitpid(p, NULL, 0);
		}
		report("fork+exec /bin/true", now_ns() - t0, n);
	}
	if (wanted("fork+exec /bin/sh -c true")) {
		double t0 = now_ns();
		for (long i = 0; i < n; i++) {
			pid_t p = fork();
			if (p == 0) {
				execl("/bin/sh", "sh", "-c", "true", (char *) NULL);
				_exit(127);
			}
			waitpid(p, NULL, 0);
		}
		report("fork+exec /bin/sh -c true", now_ns() - t0, n);
	}
}

int main(int argc, char **argv)
{
	int opt;
	while ((opt = getopt(argc, argv, "n:t:f:")) != -1) {
		switch (opt) {
		case 'n': iterations = atol(optarg); break;
		case 't': nthreads = atoi(optarg); break;
		case 'f': only_filter = 1; only_name = optarg; break;
		default:
			fprintf(stderr, "usage: %s [-n iterations] [-t threads] [-f name-substring]\n", argv[0]);
			return 2;
		}
	}
	signal(SIGPIPE, SIG_IGN);
	setup_tree();
	printf("# sysbench: %ld iterations, deep path %s\n", iterations, deep_file);

	/* --- controls: syscalls PRoot never traces --- */
	BENCH("getppid (untraced)", , syscall(SYS_getppid), );
	{
		struct timespec ts;
		BENCH("clock_gettime (vdso)", , clock_gettime(CLOCK_MONOTONIC, &ts), );
	}
	{
		int p[2]; char c = 'x';
		BENCH("pipe write+read (untraced)", pipe(p), ({ write(p[1], &c, 1); read(p[0], &c, 1); }), ({ close(p[0]); close(p[1]); }));
	}
	BENCH("mmap+munmap 4k (untraced)", , ({ void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); munmap(m, 4096); }), );
	{
		int fd;
		BENCH("fstat (untraced)", fd = open(deep_file, O_RDONLY), ({ struct stat st; fstat(fd, &st); }), close(fd));
	}

	/* --- path syscalls: one stop each --- */
	{
		struct stat st;
		BENCH("stat deep path", , stat(deep_file, &st), );
		BENCH("lstat symlink", , lstat(link_path, &st), );
		BENCH("stat ENOENT", , stat("/nonexistent/x/y", &st), );
	}
	BENCH("access deep path", , access(deep_file, R_OK), );
	BENCH("open+close deep path", , ({ int fd = open(deep_file, O_RDONLY); close(fd); }), );
	BENCH("open+close /etc/passwd", , ({ int fd = open("/etc/passwd", O_RDONLY); close(fd); }), );
	BENCH("openat ENOENT", , ({ int fd = openat(AT_FDCWD, "/nonexistent/file", O_RDONLY); if (fd >= 0) close(fd); }), );
	{
		char buf[PATH_MAX];
		BENCH("readlink", , readlink(link_path, buf, sizeof(buf)), );
		BENCH("readlink /proc/self/exe", , readlink("/proc/self/exe", buf, sizeof(buf)), );
		BENCH("getcwd", , getcwd(buf, sizeof(buf)), );
	}
	{
		int dfd;
		struct stat st;
		BENCH("fstatat relative to dirfd", dfd = open(base, O_RDONLY | O_DIRECTORY), fstatat(dfd, "link", &st, AT_SYMLINK_NOFOLLOW), close(dfd));
	}
	BENCH("statx deep path", , ({ struct statx sx; statx(AT_FDCWD, deep_file, 0, STATX_BASIC_STATS, &sx); }), );

	/* --- descriptor churn --- */
	{
		int fd;
		BENCH("dup+close", fd = open(deep_file, O_RDONLY), close(dup(fd)), close(fd));
	}

	/* --- ioctl: traced at enter and exit --- */
	{
		int p[2]; int n;
		BENCH("ioctl FIONREAD on pipe", pipe(p), ioctl(p[0], FIONREAD, &n), ({ close(p[0]); close(p[1]); }));
	}
	{
		int fd; struct winsize ws;
		fd = open("/dev/tty", O_RDONLY | O_NOCTTY);
		if (fd >= 0)
			BENCH("ioctl TIOCGWINSZ on tty", , ioctl(fd, TIOCGWINSZ, &ws), close(fd));
	}

	/* --- unix socket traffic: what X11 / Wayland / PulseAudio / D-Bus do --- */
	{
		int sv[2]; char c = 'x';
		BENCH("socketpair send+recv", socketpair(AF_UNIX, SOCK_STREAM, 0, sv), ({ send(sv[0], &c, 1, 0); recv(sv[1], &c, 1, 0); }), ({ close(sv[0]); close(sv[1]); }));
	}
	{
		int sv[2]; char c = 'x';
		struct iovec iov = { .iov_base = &c, .iov_len = 1 };
		struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1 };
		BENCH("socketpair sendmsg+recvmsg", socketpair(AF_UNIX, SOCK_STREAM, 0, sv), ({ sendmsg(sv[0], &mh, 0); recvmsg(sv[1], &mh, 0); }), ({ close(sv[0]); close(sv[1]); }));
	}
	{
		int sv[2]; char c = 'x';
		BENCH("socketpair write+read", socketpair(AF_UNIX, SOCK_STREAM, 0, sv), ({ write(sv[0], &c, 1); read(sv[1], &c, 1); }), ({ close(sv[0]); close(sv[1]); }));
	}
	{
		int sv[2]; char c = 'x';
		BENCH("socketpair sendto+recvfrom", socketpair(AF_UNIX, SOCK_DGRAM, 0, sv), ({ sendto(sv[0], &c, 1, 0, NULL, 0); recvfrom(sv[1], &c, 1, 0, NULL, NULL); }), ({ close(sv[0]); close(sv[1]); }));
	}
	{
		/* bind+connect on a unix path, like every client connecting to a daemon socket */
		char sp[PATH_MAX];
		int lfd;
		struct sockaddr_un sa = { .sun_family = AF_UNIX };
		snprintf(sp, sizeof(sp), "%s/sock", base);
		strncpy(sa.sun_path, sp, sizeof(sa.sun_path) - 1);
		lfd = socket(AF_UNIX, SOCK_STREAM, 0);
		bind(lfd, (struct sockaddr *) &sa, sizeof(sa));
		listen(lfd, 64);
		BENCH("unix socket+connect+close", , ({ int c = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0); connect(c, (struct sockaddr *) &sa, sizeof(sa)); close(c); int a = accept4(lfd, NULL, NULL, SOCK_NONBLOCK); if (a >= 0) close(a); }), close(lfd));
	}

	/* --- misc traced --- */
	{
		struct utsname { char x[65 * 6]; } u;
		BENCH("uname", , syscall(SYS_uname, &u), );
	}
	BENCH("prctl PR_GET_DUMPABLE", , syscall(SYS_prctl, 3, 0, 0, 0, 0), );

	/* --- parallelism: how badly a single tracer serialises threads --- */
	bench_threads(1);
	bench_threads(nthreads);
	bench_threads(nthreads * 4 <= 64 ? nthreads * 4 : 64);

	/* --- process creation --- */
	bench_fork();

	teardown_tree();
	return 0;
}
