#!/bin/sh
# Run sysbench natively and under proot, print both and the slowdown.
#
#   bench/run.sh [path/to/proot] [extra proot flags...]
#
# PROOT defaults to ../src/proot; SYSBENCH_ARGS passes options through
# (e.g. SYSBENCH_ARGS="-n 5000 -t 8").
set -e
here=$(dirname "$(readlink -f "$0")")
PROOT=${1:-$here/../src/proot}
[ $# -gt 0 ] && shift
make -s -C "$here" sysbench stopcost
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "## stop cost floor (independent of proot)"
"$here/stopcost"
echo
echo "## native"
"$here/sysbench" $SYSBENCH_ARGS | tee "$tmp/native"
echo
echo "## under: $PROOT $*"
"$PROOT" "$@" "$here/sysbench" $SYSBENCH_ARGS | tee "$tmp/proot"
echo
echo "## slowdown (proot / native)"
awk -F'  +' 'FNR==NR { if ($0 !~ /^#/) { n[$1]=$2+0 }; next }
     $0 !~ /^#/ { split($2,a," "); printf "%-28s %6.1fx  (%s native -> %s proot)\n", $1, (n[$1]>0 ? a[1]/n[$1] : 0), n[$1], a[1] }' \
     "$tmp/native" "$tmp/proot"
