import importlib.util
import os
import socket
import ssl
from urllib.parse import urlsplit
from urllib.request import urlopen

import pytest

from helios_bench.manifest import REPO_ROOT


@pytest.fixture
def endpoints(tmp_path):
    source = REPO_ROOT / "tools/wasi-apps/tls-smoke.py"
    spec = importlib.util.spec_from_file_location("helios_tls_smoke", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with module.Fixture(tmp_path / "fixture", os.environ.get("OPENSSL", "openssl")) as fixture:
        yield fixture


def test_local_http_and_trusted_tls_succeed(endpoints):
    http = urlsplit(endpoints.urls[0])
    with urlopen(f"http://127.0.0.1:{http.port}/success.txt", timeout=5) as response:
        assert response.read() == b"success\n"
    valid = urlsplit(endpoints.urls[1])
    context = ssl.create_default_context(cafile=str(endpoints.root / "root.crt"))
    with socket.create_connection(("127.0.0.1", valid.port), timeout=5) as connection:
        with context.wrap_socket(connection, server_hostname=valid.hostname):
            pass
    bootfs = endpoints.bootfs()
    assert (bootfs / "etc/ssl/certs/ca-certificates.crt").read_bytes() == (
        endpoints.root / "root.crt"
    ).read_bytes()


@pytest.mark.parametrize(
    ("index", "verify_code"),
    # OpenSSL X509_V_ERR_CERT_HAS_EXPIRED, IP_ADDRESS_MISMATCH,
    # and DEPTH_ZERO_SELF_SIGNED_CERT respectively.
    [(2, 10), (3, 64), (4, 18)],
)
def test_each_invalid_certificate_has_its_intended_failure(endpoints, index, verify_code):
    endpoint = urlsplit(endpoints.urls[index])
    context = ssl.create_default_context(cafile=str(endpoints.root / "root.crt"))
    with socket.create_connection(("127.0.0.1", endpoint.port), timeout=5) as connection:
        with pytest.raises(ssl.SSLCertVerificationError) as error:
            context.wrap_socket(connection, server_hostname=endpoint.hostname)
    assert error.value.verify_code == verify_code
