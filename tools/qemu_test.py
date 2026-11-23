"""QMP lifecycle shared by headless integration tests."""
import json
import socket

def quit_vm(runtime_dir):
    endpoint = runtime_dir / "sockets" / "qmp.sock"
    if not endpoint.exists():
        return
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        try:
            connection.connect(str(endpoint))
        except (ConnectionRefusedError, FileNotFoundError):
            return  # Inspector already reaped QEMU; a stale socket can remain.
        with connection.makefile("rwb", buffering=0) as stream:
            greeting = stream.readline()
            if not greeting:
                return  # QEMU exited while its socket was still present.
            json.loads(greeting)
            for command in ("qmp_capabilities", "quit"):
                stream.write(json.dumps({"execute": command}).encode() + b"\n")
                while True:
                    reply = json.loads(stream.readline())
                    if "error" in reply:
                        raise RuntimeError(reply["error"])
                    if "return" in reply:
                        break
