# bench

Syscall-heavy micro benchmarks for this PRoot.

* `sysbench.c` runs the syscalls a desktop application hammers (path
  lookups, descriptor churn, ioctl, unix socket traffic, process
  creation) plus a few untraced controls, and prints ns per operation.
* `stopcost.c` measures the floor cost of intercepting one syscall:
  plain, seccomp+ptrace stop, ptrace stop with an exit stop, and a
  seccomp user-notification round trip.
* `run.sh` builds both, runs `sysbench` natively and under proot, and
  prints the slowdown per test.

    bench/run.sh ../src/proot -r /          # or any proot + flags
    SYSBENCH_ARGS="-n 20000 -t 8" bench/run.sh /path/to/proot -R ~/proot-apps/some-app

`PROOT_NO_PATH_CACHE=1` disables the directory cache (see
`src/path/canon.c`) for an A/B comparison.
