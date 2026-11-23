#!/linux/dash
# Minimal BusyBox udhcpc hook script (#1031): applies the leased IPv4 address
# and default route via `/linux/busybox ip`.
set -eu

action="${1:-}"
case "$action" in
    deconfig)
        # Keep the interface ready while udhcpc negotiates a lease.
        ;;
    bound|renew)
        prefix="${mask:-24}"
        /linux/busybox ip addr add "${ip}/${prefix}" dev "$interface"
        if [ -n "${router:-}" ]; then
            for gw in $router; do
                /linux/busybox ip route add default via "$gw" dev "$interface"
                break
            done
        fi
        ;;
esac
