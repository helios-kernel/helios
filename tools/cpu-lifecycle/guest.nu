# Run by the guest's /bin/nu for tools/cpu-lifecycle/check.sh, which reads
# what it prints.
#
# The target is the highest possible processor: neither the bootstrap
# processor nor the one the embedded debugger runs on, so nothing the
# session itself runs is pinned to it.
let sets_line = (^cpu list | str trim)
print $"sets:before ($sets_line)"
let words = ($sets_line | split row " ")
let possible = ($words.1 | into int)
let bootstrap = ($words.3 | into int)
let target = ($possible - 1)
print $"target ($target)"

# Requests the lifecycle answers without a transition, each with its own case.
let r1 = (^cpu offline ($bootstrap | into string) | complete)
if not ($r1.stderr | is-empty) { print -n $r1.stderr }
if not ($r1.stdout | is-empty) { print -n $r1.stdout }
if $r1.exit_code != 0 { print $"status:offline-bootstrap ($r1.exit_code)" }

let r2 = (^cpu offline ($possible | into string) | complete)
if not ($r2.stderr | is-empty) { print -n $r2.stderr }
if not ($r2.stdout | is-empty) { print -n $r2.stdout }
if $r2.exit_code != 0 { print $"status:offline-not-possible ($r2.exit_code)" }

let r3 = (^cpu online ($target | into string) | complete)
if not ($r3.stderr | is-empty) { print -n $r3.stderr }
if not ($r3.stdout | is-empty) { print -n $r3.stdout }
if $r3.exit_code != 0 { print $"status:online-not-offline ($r3.exit_code)" }

# The load: the in-kernel compiler builds both programs from the host
# share, its worker threads running as global tasks on every kernel
# processor, the target among them; then curl fetches over virtio-net
# and hostcall-loop spins on host calls, concurrently with 8 lifecycle
# cycles via async `par-each`.
[
    { ^/host/curl.wasm http://detectportal.firefox.com/success.txt }
    { ^/host/hostcall-loop.wasm 2000000 }
    {
        for _ in 1..8 {
            let off = (^cpu offline ($target | into string) | complete)
            if not ($off.stdout | is-empty) { print -n $off.stdout }
            if not ($off.stderr | is-empty) { print -n $off.stderr }
            if $off.exit_code != 0 { print $"status:cycle-offline ($off.exit_code)" }

            let cur = (^cpu list | str trim)
            print $"sets:offline ($cur)"

            let again = (^cpu offline ($target | into string) | complete)
            if not ($again.stderr | is-empty) { print -n $again.stderr }
            if not ($again.stdout | is-empty) { print -n $again.stdout }
            if $again.exit_code != 0 { print $"status:offline-not-online ($again.exit_code)" }

            let on = (^cpu online ($target | into string) | complete)
            if not ($on.stdout | is-empty) { print -n $on.stdout }
            if not ($on.stderr | is-empty) { print -n $on.stderr }
            if $on.exit_code != 0 { print $"status:cycle-online ($on.exit_code)" }
        }
    }
] | par-each { |task| do $task } | ignore

let after_line = (^cpu list | str trim)
print $"sets:after ($after_line)"
print "after:ok"
