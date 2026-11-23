#!/bin/sh
# Exercises static BusyBox `ip addr`, `ip route`, and `udhcpc` (#1031) and
# verifies that WASIX `port_addr_list` and `port_route_list` report the
# resulting interface addresses and routes.
# Usage: check-busybox-netconfig.sh <busybox> <udhcpc-script> <wasix-port-list>
set -eu

bb="${1:?busybox binary required}"
dhcp_script="${2:?udhcpc script required}"
wasix_list="${3:?wasix-port-list binary required}"

has_line() {
    haystack="$1"
    needle="$2"
    case "
$haystack
" in
        *"
$needle
"*) return 0 ;;
        *) return 1 ;;
    esac
}

# 1. `ip addr show` must list lo and eth0.
addr_out="$("$bb" ip addr show)"
case "$addr_out" in
    *"lo:"*"eth0:"*|*"eth0:"*"lo:"*) ;;
    *)
        echo "busybox ip addr show missing lo/eth0: $addr_out" >&2
        exit 1
        ;;
esac

# 2. `ip addr add` and `ip route add` must be visible in both `busybox ip`
#    and WASIX `port_addr_list` / `port_route_list`.
"$bb" ip addr add 198.51.100.42/24 dev eth0
"$bb" ip route add 203.0.113.0/24 via 198.51.100.1 dev eth0

ip_addr_after="$("$bb" ip addr show dev eth0)"
case "$ip_addr_after" in
    *"198.51.100.42/24"*) ;;
    *)
        echo "busybox ip addr show missing 198.51.100.42/24: $ip_addr_after" >&2
        exit 1
        ;;
esac

ip_route_after="$("$bb" ip route show)"
case "$ip_route_after" in
    *"203.0.113.0/24"*"198.51.100.1"*) ;;
    *)
        echo "busybox ip route show missing 203.0.113.0/24 via 198.51.100.1: $ip_route_after" >&2
        exit 1
        ;;
esac

wasix_out="$("$wasix_list")"
if ! has_line "$wasix_out" "wasix-addr: 198.51.100.42/24"; then
    echo "wasix port_addr_list missing 198.51.100.42/24: $wasix_out" >&2
    exit 1
fi
if ! has_line "$wasix_out" "wasix-route: 203.0.113.0/24 via 198.51.100.1"; then
    echo "wasix port_route_list missing 203.0.113.0/24 via 198.51.100.1: $wasix_out" >&2
    exit 1
fi

# 3. Clean up the synthetic test route & address and verify removal.
"$bb" ip route del 203.0.113.0/24 via 198.51.100.1 dev eth0
"$bb" ip addr del 198.51.100.42/24 dev eth0
wasix_clean="$("$wasix_list")"
if has_line "$wasix_clean" "wasix-addr: 198.51.100.42/24"; then
    echo "wasix port_addr_list still reports deleted 198.51.100.42/24: $wasix_clean" >&2
    exit 1
fi
if has_line "$wasix_clean" "wasix-route: 203.0.113.0/24 via 198.51.100.1"; then
    echo "wasix port_route_list still reports deleted route: $wasix_clean" >&2
    exit 1
fi

# 4. Run `udhcpc` over AF_PACKET to obtain a DHCP lease and configure eth0.
"$bb" udhcpc -f -q -n -t 5 -T 2 -i eth0 -s "$dhcp_script" >/dev/null

wasix_dhcp="$("$wasix_list")"
case "$wasix_dhcp" in
    *"wasix-addr: 10.0.2.15/24"*) ;;
    *)
        echo "wasix port_addr_list missing DHCP lease 10.0.2.15/24: $wasix_dhcp" >&2
        exit 1
        ;;
esac
case "$wasix_dhcp" in
    *"wasix-route: 0.0.0.0/0 via 10.0.2.2"*) ;;
    *)
        echo "wasix port_route_list missing DHCP default route 0.0.0.0/0 via 10.0.2.2: $wasix_dhcp" >&2
        exit 1
        ;;
esac

echo "busybox-netconfig: ok"
