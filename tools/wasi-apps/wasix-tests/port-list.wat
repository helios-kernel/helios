(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))
  (import "wasix_32v1" "port_addr_list"
    (func $port_addr_list (param i32 i32) (result i32)))
  (import "wasix_32v1" "port_route_list"
    (func $port_route_list (param i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; Constant string fragments at 64..128.
  ;; "wasix-addr: "  at 64 (len 12)
  ;; "wasix-route: " at 80 (len 13)
  ;; " via "         at 96 (len 5)
  (data (i32.const 64) "wasix-addr: ")
  (data (i32.const 80) "wasix-route: ")
  (data (i32.const 96) " via ")

  ;; Append a single byte at `pos` and return `pos + 1`.
  (func $put_byte (param $pos i32) (param $b i32) (result i32)
    (i32.store8 (local.get $pos) (local.get $b))
    (i32.add (local.get $pos) (i32.const 1)))

  ;; Append `len` bytes from `src` at `pos` and return new `pos`.
  (func $put_str (param $pos i32) (param $src i32) (param $len i32) (result i32)
    (local $i i32)
    (block $done
      (loop $loop
        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
        (local.set $pos
          (call $put_byte
            (local.get $pos)
            (i32.load8_u (i32.add (local.get $src) (local.get $i)))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)))
    (local.get $pos))

  ;; Append decimal u8 (`0..255`) at `pos` and return new `pos`.
  (func $put_u8 (param $pos i32) (param $val i32) (result i32)
    (local $hundreds i32)
    (local $tens i32)
    (local.set $val (i32.and (local.get $val) (i32.const 255)))
    (local.set $hundreds (i32.div_u (local.get $val) (i32.const 100)))
    (if (local.get $hundreds)
      (then
        (local.set $pos
          (call $put_byte
            (local.get $pos)
            (i32.add (i32.const 48) (local.get $hundreds))))))
    (local.set $tens (i32.rem_u (i32.div_u (local.get $val) (i32.const 10)) (i32.const 10)))
    (if (i32.or (local.get $hundreds) (local.get $tens))
      (then
        (local.set $pos
          (call $put_byte
            (local.get $pos)
            (i32.add (i32.const 48) (local.get $tens))))))
    (call $put_byte
      (local.get $pos)
      (i32.add (i32.const 48) (i32.rem_u (local.get $val) (i32.const 10)))))

  ;; Append dotted IPv4 address from 4 bytes at `ptr`.
  (func $put_ipv4 (param $pos i32) (param $ptr i32) (result i32)
    (local.set $pos (call $put_u8 (local.get $pos) (i32.load8_u (local.get $ptr))))
    (local.set $pos (call $put_byte (local.get $pos) (i32.const 46)))
    (local.set $pos (call $put_u8 (local.get $pos) (i32.load8_u (i32.add (local.get $ptr) (i32.const 1)))))
    (local.set $pos (call $put_byte (local.get $pos) (i32.const 46)))
    (local.set $pos (call $put_u8 (local.get $pos) (i32.load8_u (i32.add (local.get $ptr) (i32.const 2)))))
    (local.set $pos (call $put_byte (local.get $pos) (i32.const 46)))
    (call $put_u8 (local.get $pos) (i32.load8_u (i32.add (local.get $ptr) (i32.const 3)))))

  (func $_start (export "_start")
    (local $err i32)
    (local $count i32)
    (local $i i32)
    (local $entry i32)
    (local $out i32)

    ;; Output buffer starts at 8192.
    (local.set $out (i32.const 8192))

    ;; Query port_addr_list(addrs=256, naddrs=12) with capacity 32.
    (i32.store (i32.const 12) (i32.const 32))
    (local.set $err (call $port_addr_list (i32.const 256) (i32.const 12)))
    (if (local.get $err)
      (then (call $proc_exit (local.get $err))))
    (local.set $count (i32.load (i32.const 12)))
    (local.set $i (i32.const 0))
    (block $addr_done
      (loop $addr_loop
        (br_if $addr_done (i32.ge_u (local.get $i) (local.get $count)))
        (local.set $entry (i32.add (i32.const 256) (i32.mul (local.get $i) (i32.const 28))))
        ;; WASIX_ADDRESS_FAMILY_IP_INET4 == 1
        (if (i32.eq (i32.load8_u (local.get $entry)) (i32.const 1))
          (then
            (local.set $out (call $put_str (local.get $out) (i32.const 64) (i32.const 12)))
            (local.set $out (call $put_ipv4 (local.get $out) (i32.add (local.get $entry) (i32.const 2))))
            (local.set $out (call $put_byte (local.get $out) (i32.const 47)))
            (local.set $out (call $put_u8 (local.get $out) (i32.load8_u (i32.add (local.get $entry) (i32.const 6)))))
            (local.set $out (call $put_byte (local.get $out) (i32.const 10)))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $addr_loop)))

    ;; Query port_route_list(routes=2048, nroutes=12) with capacity 32.
    (i32.store (i32.const 12) (i32.const 32))
    (local.set $err (call $port_route_list (i32.const 2048) (i32.const 12)))
    (if (local.get $err)
      (then (call $proc_exit (local.get $err))))
    (local.set $count (i32.load (i32.const 12)))
    (local.set $i (i32.const 0))
    (block $route_done
      (loop $route_loop
        (br_if $route_done (i32.ge_u (local.get $i) (local.get $count)))
        (local.set $entry (i32.add (i32.const 2048) (i32.mul (local.get $i) (i32.const 176))))
        (if (i32.eq (i32.load8_u (local.get $entry)) (i32.const 1))
          (then
            (local.set $out (call $put_str (local.get $out) (i32.const 80) (i32.const 13)))
            (local.set $out (call $put_ipv4 (local.get $out) (i32.add (local.get $entry) (i32.const 2))))
            (local.set $out (call $put_byte (local.get $out) (i32.const 47)))
            (local.set $out (call $put_u8 (local.get $out) (i32.load8_u (i32.add (local.get $entry) (i32.const 6)))))
            (local.set $out (call $put_str (local.get $out) (i32.const 96) (i32.const 5)))
            (local.set $out (call $put_ipv4 (local.get $out) (i32.add (local.get $entry) (i32.const 30))))
            (local.set $out (call $put_byte (local.get $out) (i32.const 10)))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $route_loop)))

    ;; Write output buffer to stdout (fd 1).
    (i32.store (i32.const 0) (i32.const 8192))
    (i32.store (i32.const 4) (i32.sub (local.get $out) (i32.const 8192)))
    (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8))))
)
