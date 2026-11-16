#!/bin/sh
set --
while IFS= read -r url; do
    set -- "$@" "$url"
done < /etc/tls-smoke-urls
test "$(curl "$1")" = success || exit 1
test "$(curl "$2")" = success || exit 1
shift 2
for url do
    if curl "$url"; then
        exit 1
    fi
done
echo tls-smoke:ok
