#!/usr/bin/env python3
"""Serve the HTTP/TLS smoke endpoints locally, then drive one real guest."""

from __future__ import annotations

import argparse
import contextlib
import csv
import http.server
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlunsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
GUEST_HOST = "10.0.2.2"  # QEMU user networking's host-loopback address.


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"success\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class Fixture:
    def __init__(self, root: Path, openssl: str = "openssl"):
        self.root = root
        self.openssl = openssl
        self.servers = contextlib.ExitStack()

    def command(self, *args: str):
        subprocess.run(
            [self.openssl, *args], cwd=self.root, check=True, capture_output=True
        )

    def request(self, name: str, san: str, *, authority: bool = False):
        self.command(
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            f"{name}.key",
            "-out",
            f"{name}.csr",
            "-subj",
            f"/CN={name}",
            "-addext",
            f"subjectAltName={san}",
            "-addext",
            f"basicConstraints=critical,CA:{'TRUE' if authority else 'FALSE'}",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign"
            if authority
            else "keyUsage=critical,digitalSignature",
        )

    def certificate(
        self, name: str, *, self_signed: bool = False, expired: bool = False
    ):
        if expired:
            now = datetime.now(timezone.utc)
            (self.root / "index.txt").touch()
            (self.root / "serial").write_text("01\n")
            (self.root / "issued").mkdir()
            self.command(
                "ca",
                "-batch",
                "-config",
                str(Path(__file__).with_suffix(".cnf")),
                "-in",
                f"{name}.csr",
                "-out",
                f"{name}.crt",
                "-notext",
                "-startdate",
                (now - timedelta(days=2)).strftime("%Y%m%d%H%M%SZ"),
                "-enddate",
                (now - timedelta(days=1)).strftime("%Y%m%d%H%M%SZ"),
            )
            return
        signing = (
            ["-signkey", f"{name}.key"]
            if self_signed
            else ["-CA", "root.crt", "-CAkey", "root.key", "-CAcreateserial"]
        )
        self.command(
            "x509",
            "-req",
            "-in",
            f"{name}.csr",
            "-out",
            f"{name}.crt",
            "-copy_extensions",
            "copy",
            "-days",
            "2",
            *signing,
        )

    def start(self, certificate: str | None) -> str:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if certificate is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(
                self.root / f"{certificate}.crt", self.root / f"{certificate}.key"
            )
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.servers.callback(server.server_close)
        self.servers.callback(thread.join)
        self.servers.callback(server.shutdown)
        scheme = "http" if certificate is None else "https"
        return urlunsplit(
            (scheme, f"{GUEST_HOST}:{server.server_port}", "/success.txt", "", "")
        )

    def __enter__(self):
        self.root.mkdir(parents=True)
        self.request("root", "DNS:helios-smoke-root", authority=True)
        self.certificate("root", self_signed=True)
        for name in ("valid", "expired", "wrong-host", "self-signed"):
            san = "DNS:wrong.invalid" if name == "wrong-host" else f"IP:{GUEST_HOST}"
            self.request(name, san)
            self.certificate(
                name, self_signed=name == "self-signed", expired=name == "expired"
            )
        with contextlib.ExitStack() as startup:
            startup.callback(self.servers.close)
            self.urls = [self.start(None)]
            self.urls.extend(
                self.start(name)
                for name in ("valid", "expired", "wrong-host", "self-signed")
            )
            startup.pop_all()
        return self

    def __exit__(self, *_exc):
        self.servers.close()

    def bootfs(self) -> Path:
        destination = self.root / "bootfs"
        shutil.copytree(REPO_ROOT / "programs/init/bootfs", destination)
        bundle = destination / "etc/ssl/certs/ca-certificates.crt"
        bundle.parent.mkdir(parents=True)
        shutil.copyfile(self.root / "root.crt", bundle)
        with (destination / "etc/tls-smoke-urls").open("w", newline="") as urls:
            csv.writer(urls, lineterminator="\n").writerows((url,) for url in self.urls)
        return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--accel", required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument(
        "--inspector", type=Path, default=REPO_ROOT / "target/release/helios"
    )
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    args.runtime_dir.mkdir(parents=True, exist_ok=True)
    with (
        tempfile.TemporaryDirectory(prefix="helios-tls-smoke-") as temporary,
        Fixture(Path(temporary) / "fixture", args.openssl) as fixture,
    ):
        command = [
            str(args.inspector),
            "vm",
            "--arch",
            args.arch,
            "--release",
            "--memory",
            "2G",
            "--accel",
            args.accel,
            "--runtime-dir",
            str(args.runtime_dir),
            "--keep-runtime-dir",
            "--bootfs-root",
            str(fixture.bootfs()),
            "--boot-program",
            "dash",
            "--boot-program",
            "debugger",
            "--boot-program",
            "curl",
            "--boot-program",
            "http-client",
            "--no-compiler-plugin",
            "shell",
            "-c",
            Path(__file__).with_suffix(".sh").read_text(),
        ]
        result = subprocess.run(
            command, cwd=REPO_ROOT, capture_output=True, text=True, check=False
        )
    transcript = result.stdout + result.stderr
    (args.runtime_dir / "inspector.log").write_text(transcript)
    sys.stdout.write(transcript)
    if result.returncode != 0:
        raise SystemExit(f"TLS smoke guest exited with {result.returncode}")
    if "tls-smoke:ok" not in result.stdout.splitlines():
        raise SystemExit("TLS smoke did not accept both valid HTTP and TLS responses")
    certificate_error = (
        "the server's certificate did not verify: ErrorCode::TlsCertificateError"
    )
    if transcript.count(certificate_error) != 3:
        raise SystemExit(
            "TLS smoke expected expired, wrong-host and self-signed certificate refusals"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
