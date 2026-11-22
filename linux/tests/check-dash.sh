#!/bin/sh
# Exercises a static musl `dash` binary (#1034): pipelines, subshells,
# background jobs, `wait`, and mixing Linux and WASIX children.
# Runs on Linux (in build-fixtures.sh) and on Helios (smoke-x86-64,
# smoke-aarch64).
# Usage: check-dash.sh <dash> <linux-hello> <linux-args> <cat-program>
set -eu

dash_bin="${1:?dash binary required}"
linux_hello="${2:?linux hello binary required}"
linux_args="${3:?linux args binary required}"
cat_prog="${4:?cat binary required}"

# 1. Pipelines (including Linux -> cat -> cat multi-stage pipeline and command substitution).
pipe_out="$("$dash_bin" -c "$linux_hello | $cat_prog | $cat_prog")"
if [ "$pipe_out" != "native Linux syscall: ok" ]; then
    echo "dash pipeline failed: got '$pipe_out'" >&2
    exit 1
fi

args_pipe="$("$dash_bin" -c "$linux_args 0 中文 日本語 한국어 | $cat_prog")"
case "$args_pipe" in
    *"arg2=中文"*"arg3=日本語"*"arg4=한국어"*) ;;
    *)
        echo "dash CJK pipeline failed: got '$args_pipe'" >&2
        exit 1
        ;;
esac

# 2. Subshells: variable isolation and exit status propagation.
sub_out="$("$dash_bin" -c '
x=outer
(x=inner; printf "in:%s " "$x"; exit 7)
rc=$?
printf "out:%s rc:%d\n" "$x" "$rc"
')"
if [ "$sub_out" != "in:inner out:outer rc:7" ]; then
    echo "dash subshell failed: got '$sub_out'" >&2
    exit 1
fi

# 3. Background jobs and `wait` (by PID and wait-all), mixing Linux and WASIX/cat children.
bg_out="$("$dash_bin" -c "
($linux_args 5 a >/dev/null; exit \$?) &
p1=\$!
($linux_hello | $cat_prog >/dev/null) &
p2=\$!
(exit 11) &
p3=\$!
wait \$p1
r1=\$?
wait \$p2
r2=\$?
wait \$p3
r3=\$?
echo \"bg:\$r1:\$r2:\$r3\"
")"
if [ "$bg_out" != "bg:5:0:11" ]; then
    echo "dash background wait failed: got '$bg_out'" >&2
    exit 1
fi

echo "dash: ok"
