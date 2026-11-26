#!/bin/sh
# Exercises full defconfig BusyBox 1.36.1 applets (#1261) across applet
# inventory, standalone `/proc/self/exe` dispatch, shells (`ash`, `hush`),
# `procps` & system inspection, `coreutils` & `util-linux`, archival &
# compression, text & math, and networking.
#
# Runs natively on Linux (in `build-fixtures.sh`) and inside a single Helios
# Linux container (in `smoke-x86-64` and `smoke-aarch64`). When launched from
# another shell (e.g. WASIX `/bin/dash` or host `sh`), re-invokes itself under
# `"$bb" ash` so all child processes share one PID/IPC/mount namespace.
#
# Usage: check-busybox.sh <busybox> [memory-fixture]
set -eu

if [ "${1:-}" != "--in-ash" ]; then
    bb="${1:?busybox binary required}"
    shift
    "$bb" ash "$0" --in-ash "$bb" "$@"
    exit $?
fi
shift

bb_arg="${1:?busybox binary required}"
memory_arg="${2:-}"

bb="$("$bb_arg" realpath "$bb_arg")"
memory_bin=""
if [ -n "$memory_arg" ]; then
    memory_bin="$("$bb" realpath "$memory_arg")"
fi

fail() {
    echo "check-busybox failed: $*" >&2
    exit 1
}

assert_eq() {
    label="$1"
    got="$2"
    want="$3"
    if [ "$got" != "$want" ]; then
        fail "$label: expected '$want', got '$got'"
    fi
}

assert_contains() {
    label="$1"
    haystack="$2"
    needle="$3"
    case "$haystack" in
        *"$needle"*) ;;
        *) fail "$label: expected to contain '$needle', got '$haystack'" ;;
    esac
}

"$bb" mkdir -p /tmp
work="$("$bb" mktemp -d /tmp/check-busybox.XXXXXX)"
httpd_pid=""
bg_pids=""
cleanup() {
    if [ -n "$httpd_pid" ]; then
        kill "$httpd_pid" 2>/dev/null || true
    fi
    for p in $bg_pids; do
        kill "$p" 2>/dev/null || true
    done
    "$bb" rm -rf "$work"
}
trap cleanup EXIT

"$bb" mkdir -p "$work/bin"

# ---------------------------------------------------------------------------
# 1. Applet inventory, symlink install, and `/proc/self/exe` dispatch
# ---------------------------------------------------------------------------
applet_list="$("$bb" --list)"
applet_count="$(printf '%s\n' "$applet_list" | "$bb" wc -l | "$bb" tr -d ' ')"
if [ "$applet_count" -lt 400 ]; then
    fail "applet count too low: $applet_count (expected >= 400 from defconfig)"
fi

"$bb" --install -s "$work/bin"
export PATH="$work/bin:$PATH"
export SHELL="$work/bin/ash"

assert_eq "symlink echo" "$("$work/bin/echo" "中文 日本語 한국어")" "中文 日本語 한국어"
assert_eq "symlink wc" "$(printf 'a\nb\nc\n' | "$work/bin/wc" -l | "$work/bin/tr" -d ' ')" "3"
"$work/bin/true"
if "$work/bin/false"; then
    fail "symlink false returned 0"
fi

# `/proc/self/exe` inside BusyBox `ash` resolves to the BusyBox binary itself;
# symlinking applet names to `/proc/self/exe` exercises kernel `/proc/self/exe`
# resolution on execve while setting `argv[0]` to the target applet name.
self_exe="$("$bb" ash -c 'readlink /proc/self/exe')"
assert_eq "readlink /proc/self/exe" "$self_exe" "$bb"
mkdir -p "$work/self-bin"
ln -s /proc/self/exe "$work/self-bin/busybox"
ln -s /proc/self/exe "$work/self-bin/echo"
self_dispatch="$("$bb" ash -c '"$1"/busybox echo "proc-self-exe: 中文 日本語 한국어"' _ "$work/self-bin")"
assert_eq "/proc/self/exe busybox dispatch" "$self_dispatch" "proc-self-exe: 中文 日本語 한국어"
self_applet="$("$bb" ash -c '"$1"/echo "proc-self-applet: 中文 日本語 한국어"' _ "$work/self-bin")"
assert_eq "/proc/self/exe applet dispatch" "$self_applet" "proc-self-applet: 中文 日本語 한국어"

# ---------------------------------------------------------------------------
# 2. Shells (`ash` and `hush`)
# ---------------------------------------------------------------------------
check_shell() {
    sh_name="$1"
    sh_bin="$work/bin/$sh_name"

    # Pipelines, command substitution, subshells, redirections, conditionals,
    # functions, arithmetic, background wait, `times`, and CJK payloads.
    out="$("$sh_bin" -c '
        set -e
        add_mul() {
            echo $(( ($1 + $2) * 6 ))
        }
        v="$(add_mul 3 4)"
        x=outer
        (x=inner; printf "%s:" "$x"; exit 9) && rc=0 || rc=$?
        printf "%s:%s:%s\n" "$v" "$x" "$rc"
        if [ "$v" -eq 42 ] && [ "$rc" -eq 9 ]; then
            echo "cond:ok"
        else
            echo "cond:bad"
        fi
        case "$1" in
            "中文 日本語 한국어") echo "cjk:$1" ;;
            *) echo "cjk:bad" ;;
        esac
        printf "line1\nline2\n" > "'"$work"'/redir-'"$sh_name"'.txt"
        printf "line3\n" >> "'"$work"'/redir-'"$sh_name"'.txt"
        lines="$(wc -l < "'"$work"'/redir-'"$sh_name"'.txt" | tr -d " ")"
        err_out="$( (echo stderr-msg >&2) 2>&1 )"
        echo "redir:${lines}:${err_out}"
        (sleep 0; exit 13) &
        bg_pid=$!
        wait "$bg_pid" && bg_rc=0 || bg_rc=$?
        echo "bg:${bg_rc}"
        t_out="$(times)"
        if [ -n "$t_out" ]; then
            echo "times:ok"
        fi
    ' _ "中文 日本語 한국어")"

    assert_contains "$sh_name arithmetic/subshell" "$out" "inner:42:outer:9"
    assert_contains "$sh_name cond" "$out" "cond:ok"
    assert_contains "$sh_name cjk" "$out" "cjk:中文 日本語 한국어"
    assert_contains "$sh_name redir" "$out" "redir:3:stderr-msg"
    assert_contains "$sh_name bg wait" "$out" "bg:13"
    assert_contains "$sh_name times" "$out" "times:ok"
}

check_shell ash
check_shell hush

# Interactive job control (`set -m`, background job, `jobs`, `fg`/`wait`)
# over a real PTY allocated by BusyBox `script`.
"$bb" script -q -c "$work/bin/ash -c '
    set -m
    sleep 1 &
    jobs_out=\$(jobs)
    case \"\$jobs_out\" in
        *\"[1]\"*) echo \"jobctl-jobs:ok\" ;;
        *) echo \"jobctl-jobs:bad:\$jobs_out\"; exit 1 ;;
    esac
    fg %1 >/dev/null 2>&1 || wait %1
    echo \"jobctl-fg:ok\"
'" "$work/jobctl.typescript" >/dev/null
jobctl_log="$(cat "$work/jobctl.typescript")"
assert_contains "ash jobctl jobs" "$jobctl_log" "jobctl-jobs:ok"
assert_contains "ash jobctl fg" "$jobctl_log" "jobctl-fg:ok"

# ---------------------------------------------------------------------------
# 3. `procps` & system inspection
# ---------------------------------------------------------------------------
ps_out="$("$bb" ps)"
assert_contains "ps header" "$ps_out" "PID"

top_out="$("$bb" top -bn1)"
assert_contains "top Mem" "$top_out" "Mem:"
assert_contains "top PID" "$top_out" "PID"

free_out="$("$bb" free)"
assert_contains "free Mem" "$free_out" "Mem:"

uptime_out="$("$bb" uptime)"
assert_contains "uptime up" "$uptime_out" "up"
assert_contains "uptime load" "$uptime_out" "load average"

uname_out="$("$bb" uname -a)"
assert_contains "uname Linux" "$uname_out" "Linux"

id_out="$("$bb" id)"
assert_contains "id uid" "$id_out" "uid="
assert_contains "id gid" "$id_out" "gid="

host_out="$("$bb" hostname)"
if [ -z "$host_out" ]; then
    fail "hostname returned empty string"
fi

sysctl_ostype="$("$bb" sysctl kernel.ostype)"
assert_contains "sysctl kernel.ostype" "$sysctl_ostype" "Linux"
sysctl_all="$("$bb" sysctl -a 2>/dev/null || true)"
assert_contains "sysctl -a" "$sysctl_all" "kernel."

# `pgrep`, `pkill`, `pidof`: spawn a uniquely-tagged background sleep via ash
# and a direct `sleep` symlink child so both `pidof sleep` and `pgrep`/`pkill`
# match deterministically without disturbing unrelated processes on host Linux.
tag="bbtag_$$"
"$work/bin/sleep" 30 &
sleep_pid=$!
bg_pids="$bg_pids $sleep_pid"

pidof_out="$("$bb" pidof sleep)"
assert_contains "pidof sleep" " $pidof_out " " $sleep_pid "

"$work/bin/ash" -c 'sleep 30' "$tag" &
tagged_ash_pid=$!
bg_pids="$bg_pids $tagged_ash_pid"

pgrep_out="$("$bb" pgrep -f "$tag")"
assert_contains "pgrep -f" " $(echo "$pgrep_out" | tr '\n' ' ') " " $tagged_ash_pid "

"$bb" pkill -f "$tag"
wait "$tagged_ash_pid" 2>/dev/null || true
kill "$sleep_pid" 2>/dev/null || true
wait "$sleep_pid" 2>/dev/null || true
bg_pids=""

# `pmap`, `pwdx`, `lsof` against our own Linux `ash` process (`$$`).
pmap_out="$("$bb" pmap "$$")"
assert_contains "pmap pid" "$pmap_out" "$$:"

pwdx_out="$("$work/bin/ash" -c 'cd "$1" && pwdx "$$"' _ "$work")"
assert_contains "pwdx cwd" "$pwdx_out" "$work"

exec 3>"$work/lsof-probe.txt"
lsof_out="$("$bb" lsof)"
exec 3>&-
assert_contains "lsof open file" "$lsof_out" "lsof-probe.txt"

# ---------------------------------------------------------------------------
# 4. `coreutils` & `util-linux`
# ---------------------------------------------------------------------------
df_out="$("$bb" df "$work")"
assert_contains "df header" "$df_out" "Filesystem"

du_out="$("$bb" du -s "$work")"
if [ -z "$du_out" ]; then
    fail "du returned empty output"
fi

printf '0123456789' > "$work/stat-target.txt"
assert_eq "stat size" "$("$bb" stat -c '%s' "$work/stat-target.txt")" "10"
stat_priv="/dev/shm/check-busybox-stat-$$.tmp"
printf '0123456789' > "$stat_priv"
chmod 640 "$stat_priv"
assert_eq "stat size+mode" "$("$bb" stat -c '%s %a' "$stat_priv")" "10 640"
rm -f "$stat_priv"
statf_out="$("$bb" stat -f -c '%s' "$work")"
if [ -z "$statf_out" ] || [ "$statf_out" -le 0 ]; then
    fail "stat -f returned invalid block size: '$statf_out'"
fi

# `flock`: exclusive and shared lock contention with `flock -n`.
lockfile="$work/test.lock"
: > "$lockfile"
"$bb" mkfifo "$work/lock-ready.fifo" "$work/lock-done.fifo"

# Exclusive holder blocks both `-n -x` and `-n -s`.
(
    exec 9>"$lockfile"
    "$bb" flock -x 9
    printf 'locked\n' > "$work/lock-ready.fifo"
    read -r _ < "$work/lock-done.fifo"
) &
flock_pid=$!
read -r ready_msg < "$work/lock-ready.fifo"
assert_eq "flock exclusive ready" "$ready_msg" "locked"
if "$bb" flock -n -x "$lockfile" true 2>/dev/null; then
    fail "flock -n -x succeeded while exclusive lock was held"
fi
if "$bb" flock -n -s "$lockfile" true 2>/dev/null; then
    fail "flock -n -s succeeded while exclusive lock was held"
fi
printf 'go\n' > "$work/lock-done.fifo"
wait "$flock_pid"

# Shared holder allows `-n -s` and blocks `-n -x`.
(
    exec 9>"$lockfile"
    "$bb" flock -s 9
    printf 'shared\n' > "$work/lock-ready.fifo"
    read -r _ < "$work/lock-done.fifo"
) &
flock_pid=$!
read -r ready_msg < "$work/lock-ready.fifo"
assert_eq "flock shared ready" "$ready_msg" "shared"
"$bb" flock -n -s "$lockfile" true || fail "flock -n -s failed while shared lock was held"
if "$bb" flock -n -x "$lockfile" true 2>/dev/null; then
    fail "flock -n -x succeeded while shared lock was held"
fi
printf 'go\n' > "$work/lock-done.fifo"
wait "$flock_pid"

# `fallocate`
"$bb" fallocate -l 4096 "$work/alloc.bin"
assert_eq "fallocate size" "$("$bb" stat -c '%s' "$work/alloc.bin")" "4096"

# `chroot` (requires root / CAP_SYS_CHROOT; always uid 0 inside Helios).
if [ "$("$bb" id -u)" = "0" ]; then
    mkdir -p "$work/chroot-root/bin"
    cp "$bb" "$work/chroot-root/bin/busybox"
    chmod +x "$work/chroot-root/bin/busybox"
    printf 'chroot-ok: 中文 日本語 한국어\n' > "$work/chroot-root/marker.txt"
    chroot_out="$("$bb" chroot "$work/chroot-root" /bin/busybox cat /marker.txt)"
    assert_eq "chroot cat" "$chroot_out" "chroot-ok: 中文 日本語 한국어"
fi

# `taskset`: query current CPU affinity and narrow to CPU 0 (`0x1`).
taskset_before="$("$bb" taskset -p "$$")"
assert_contains "taskset query" "$taskset_before" "affinity mask:"
taskset_child="$("$bb" taskset 0x1 "$work/bin/ash" -c 'taskset -p "$$"')"
assert_contains "taskset narrowed" "$taskset_child" ": 1"

# `mkfifo`: named pipe reader/writer rendezvous with CJK payload.
"$bb" mkfifo "$work/rendezvous.fifo"
(printf 'fifo-ok: 中文 日本語 한국어\n' > "$work/rendezvous.fifo") &
fifo_writer=$!
fifo_line="$(cat "$work/rendezvous.fifo")"
wait "$fifo_writer"
assert_eq "mkfifo rendezvous" "$fifo_line" "fifo-ok: 中文 日本語 한국어"

# `ipcs` & `ipcrm`
ipcs_hdr="$("$bb" ipcs -m)"
assert_contains "ipcs -m header" "$ipcs_hdr" "Shared Memory Segments"
if [ -n "$memory_bin" ] && [ -x "$memory_bin" ]; then
    shmid="$("$memory_bin" shm-create)"
    ipcs_after="$("$bb" ipcs -m)"
    assert_contains "ipcs -m lists created shmid" "$ipcs_after" "$shmid"
    "$bb" ipcrm -m "$shmid"
    ipcs_removed="$("$bb" ipcs -m)"
    case "$ipcs_removed" in
        *" $shmid "*) fail "ipcrm -m did not remove shmid $shmid: $ipcs_removed" ;;
    esac
fi

# `script` over PTY (`/dev/ptmx` + `/dev/pts/*`).
"$bb" script -q -c "$bb echo 'pty-ok: 中文 日本語 한국어'" "$work/pty.typescript" >/dev/null
pty_out="$(cat "$work/pty.typescript")"
assert_contains "script pty output" "$pty_out" "pty-ok: 中文 日本語 한국어"

# Device nodes: `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/urandom`, `/dev/shm`.
printf 'discard-me\n' > /dev/null
null_read="$(cat /dev/null)"
assert_eq "/dev/null read" "$null_read" ""

zero_hex="$("$bb" dd if=/dev/zero bs=16 count=1 2>/dev/null | "$bb" od -An -tx1 | "$bb" tr -d ' \n')"
assert_eq "/dev/zero 16 bytes" "$zero_hex" "00000000000000000000000000000000"

if "$bb" dd if=/dev/zero of=/dev/full bs=1 count=1 2>/dev/null; then
    fail "write to /dev/full succeeded (expected ENOSPC)"
fi

rand_len="$("$bb" dd if=/dev/urandom bs=16 count=1 2>/dev/null | "$bb" wc -c | "$bb" tr -d ' ')"
assert_eq "/dev/urandom len" "$rand_len" "16"

if [ ! -d /dev/shm ]; then
    fail "/dev/shm is not a directory"
fi
shm_probe="/dev/shm/check-busybox-$$.tmp"
printf 'shm-ok: 中文 日本語 한국어\n' > "$shm_probe"
assert_eq "/dev/shm file" "$(cat "$shm_probe")" "shm-ok: 中文 日本語 한국어"
rm -f "$shm_probe"

# ---------------------------------------------------------------------------
# 5. Archival & compression
# ---------------------------------------------------------------------------
mkdir -p "$work/arch/src/sub"
printf 'archive-payload: 中文 日本語 한국어\n' > "$work/arch/src/sub/data.txt"

# Plain tar
"$bb" tar -cf "$work/arch/plain.tar" -C "$work/arch/src" .
mkdir -p "$work/arch/out-plain"
"$bb" tar -xf "$work/arch/plain.tar" -C "$work/arch/out-plain"
"$bb" cmp "$work/arch/src/sub/data.txt" "$work/arch/out-plain/sub/data.txt"

# gzip tar + standalone gzip/gunzip
"$bb" tar -czf "$work/arch/gz.tar.gz" -C "$work/arch/src" .
mkdir -p "$work/arch/out-gz"
"$bb" tar -xzf "$work/arch/gz.tar.gz" -C "$work/arch/out-gz"
"$bb" cmp "$work/arch/src/sub/data.txt" "$work/arch/out-gz/sub/data.txt"

cp "$work/arch/src/sub/data.txt" "$work/arch/gz-standalone.txt"
"$bb" gzip "$work/arch/gz-standalone.txt"
"$bb" gunzip "$work/arch/gz-standalone.txt.gz"
"$bb" cmp "$work/arch/src/sub/data.txt" "$work/arch/gz-standalone.txt"

# bzip2 tar + standalone bzip2/bunzip2
"$bb" tar -cjf "$work/arch/bz2.tar.bz2" -C "$work/arch/src" .
mkdir -p "$work/arch/out-bz2"
"$bb" tar -xjf "$work/arch/bz2.tar.bz2" -C "$work/arch/out-bz2"
"$bb" cmp "$work/arch/src/sub/data.txt" "$work/arch/out-bz2/sub/data.txt"

cp "$work/arch/src/sub/data.txt" "$work/arch/bz2-standalone.txt"
"$bb" bzip2 "$work/arch/bz2-standalone.txt"
"$bb" bunzip2 "$work/arch/bz2-standalone.txt.bz2"
"$bb" cmp "$work/arch/src/sub/data.txt" "$work/arch/bz2-standalone.txt"

# xz decompression (`xz -d`, `unxz`, `tar -xJf`). BusyBox 1.36.1 ships the
# XZ decompressor only; emit tiny valid XZ and tar.xz streams with printf.
"$bb" printf '\375\067\172\130\132\000\000\004\346\326\264\106\002\000\041\001\026\000\000\000\164\057\345\243\001\000\041\170\172\055\157\153\072\040\344\270\255\346\226\207\040\346\227\245\346\234\254\350\252\236\040\355\225\234\352\265\255\354\226\264\012\000\000\000\265\347\015\164\265\351\341\224\000\001\072\042\266\052\117\320\037\266\363\175\001\000\000\000\000\004\131\132' \
    > "$work/arch/sample.xz"
assert_eq "xz -dc" "$("$bb" xz -dc "$work/arch/sample.xz")" "xz-ok: 中文 日本語 한국어"
cp "$work/arch/sample.xz" "$work/arch/sample2.xz"
"$bb" unxz "$work/arch/sample2.xz"
assert_eq "unxz" "$(cat "$work/arch/sample2")" "xz-ok: 中文 日本語 한국어"

"$bb" printf '\375\067\172\130\132\000\000\004\346\326\264\106\002\000\041\001\026\000\000\000\164\057\345\243\340\047\377\000\204\135\000\064\031\111\356\215\360\272\310\377\233\377\362\014\151\257\021\353\143\124\211\035\367\056\037\240\216\377\235\260\071\122\071\131\236\010\321\110\252\123\271\215\130\014\232\364\270\131\260\005\236\316\323\352\251\232\356\220\142\002\102\100\335\215\115\361\301\270\330\166\227\067\344\377\025\021\317\276\105\316\056\263\055\107\311\334\025\340\250\331\024\243\123\025\105\366\314\205\077\125\215\161\142\122\072\207\314\314\331\062\134\006\170\270\127\003\321\276\166\170\241\066\257\340\157\006\034\256\352\354\043\134\000\000\067\004\277\244\376\061\233\344\000\001\240\001\200\120\000\000\010\164\314\146\261\304\147\373\002\000\000\000\000\004\131\132' \
    > "$work/arch/sample.tar.xz"
mkdir -p "$work/arch/out-xz"
"$bb" tar -xJf "$work/arch/sample.tar.xz" -C "$work/arch/out-xz"
assert_eq "tar -xJf" "$(cat "$work/arch/out-xz/hello.txt")" "tar-xz-ok: 中文 日本語 한국어"

# `unzip`: generate a valid stored PKZIP archive (151 bytes) containing hello.txt.
"$bb" printf '\120\113\003\004\024\000\000\000\000\000\131\014\172\135\347\226\052\053\043\000\000\000\043\000\000\000\011\000\000\000\150\145\154\154\157\056\164\170\164\172\151\160\055\157\153\072\040\344\270\255\346\226\207\040\346\227\245\346\234\254\350\252\236\040\355\225\234\352\265\255\354\226\264\012\120\113\001\002\024\003\024\000\000\000\000\000\131\014\172\135\347\226\052\053\043\000\000\000\043\000\000\000\011\000\000\000\000\000\000\000\000\000\000\000\200\001\000\000\000\000\150\145\154\154\157\056\164\170\164\120\113\005\006\000\000\000\000\001\000\001\000\067\000\000\000\112\000\000\000\000\000' \
    > "$work/arch/sample.zip"
mkdir -p "$work/arch/out-zip"
"$bb" unzip -q "$work/arch/sample.zip" -d "$work/arch/out-zip"
assert_eq "unzip" "$(cat "$work/arch/out-zip/hello.txt")" "zip-ok: 中文 日本語 한국어"

# `cpio` (`-o -H newc` / `-id`)
(cd "$work/arch/src" && "$bb" find . -print | "$bb" cpio -o -H newc > "$work/arch/sample.cpio" 2>/dev/null)
mkdir -p "$work/arch/out-cpio"
(cd "$work/arch/out-cpio" && "$bb" cpio -id < "$work/arch/sample.cpio" 2>/dev/null)
"$bb" cmp "$work/arch/src/sub/data.txt" "$work/arch/out-cpio/sub/data.txt"

# ---------------------------------------------------------------------------
# 6. Text & math
# ---------------------------------------------------------------------------
assert_eq "awk" "$(printf 'a 10\nb 32\n' | "$bb" awk '{s+=$2} END{print s}')" "42"
assert_eq "sed" "$(printf 'hello world\n' | "$bb" sed 's/world/helios/')" "hello helios"
assert_eq "grep cjk" "$(printf 'alpha\n中文 日本語 한국어\nbeta\n' | "$bb" grep '日本語')" "中文 日本語 한국어"

printf 'one\ntwo\nthree\n' > "$work/v1.txt"
printf 'one\nTWO\nthree\nfour\n' > "$work/v2.txt"
"$bb" diff -u "$work/v1.txt" "$work/v2.txt" > "$work/v.patch" || true
cp "$work/v1.txt" "$work/v1-patched.txt"
"$bb" patch "$work/v1-patched.txt" < "$work/v.patch" >/dev/null
"$bb" cmp "$work/v1-patched.txt" "$work/v2.txt"

mkdir -p "$work/fx"
printf 'A' > "$work/fx/1.item"
printf 'B' > "$work/fx/2.item"
fx_out="$("$bb" find "$work/fx" -name '*.item' | "$bb" sort | "$bb" xargs "$bb" cat)"
assert_eq "find+xargs" "$fx_out" "AB"

assert_eq "bc" "$(printf '6 * 7\n' | "$bb" bc)" "42"
assert_eq "dc" "$(printf '6 7 * p\n' | "$bb" dc)" "42"

# ---------------------------------------------------------------------------
# 7. Networking
# ---------------------------------------------------------------------------
assert_contains "ip link" "$("$bb" ip link show)" "lo:"
assert_contains "ip addr" "$("$bb" ip addr show)" "127.0.0.1"
"$bb" ip route show >/dev/null
assert_contains "ifconfig" "$("$bb" ifconfig)" "127.0.0.1"
assert_contains "route -n" "$("$bb" route -n)" "Destination"

mkdir -p "$work/www"
printf 'httpd-ok: 中文 日本語 한국어\n' > "$work/www/index.html"

http_port=$((18080 + ($$ % 1000)))
"$bb" httpd -f -p "127.0.0.1:${http_port}" -h "$work/www" &
httpd_pid=$!

# Wait briefly for httpd to enter LISTEN.
ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if "$bb" wget -qO- "http://127.0.0.1:${http_port}/index.html" > "$work/wget.out" 2>/dev/null; then
        ready=1
        break
    fi
    "$bb" usleep 50000
done
if [ "$ready" -ne 1 ]; then
    fail "httpd on 127.0.0.1:${http_port} never answered wget"
fi
assert_eq "httpd+wget" "$(cat "$work/wget.out")" "httpd-ok: 中文 日本語 한국어"

nc_out="$(printf 'GET /index.html HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n' | "$bb" nc 127.0.0.1 "$http_port")"
assert_contains "httpd+nc status" "$nc_out" "200 OK"
assert_contains "httpd+nc body" "$nc_out" "httpd-ok: 中文 日本語 한국어"

netstat_out="$("$bb" netstat -ltn)"
assert_contains "netstat listen port" "$netstat_out" ":${http_port}"

kill "$httpd_pid" 2>/dev/null || true
wait "$httpd_pid" 2>/dev/null || true
httpd_pid=""

# `ping`: BusyBox 1.36.1 opens `SOCK_RAW` `IPPROTO_ICMP` (requires `CAP_NET_RAW`).
# Always run unconditionally when uid 0 (Helios guest container and root Linux).
if [ "$("$bb" id -u)" = "0" ]; then
    ping_out="$("$bb" ping -c 1 -W 2 127.0.0.1)"
    assert_contains "ping 127.0.0.1" "$ping_out" "1 packets received"
fi

echo "busybox: ok"
