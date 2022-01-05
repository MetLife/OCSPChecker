""" Tests """
import pytest
from ocspchecker.ocspchecker import (
    build_ocsp_request,
    extract_ocsp_result,
    extract_ocsp_url,
    get_certificate_chain,
    get_ocsp_response,
    get_ocsp_status,
)

from . import certs


def test_get_cert_chain_bad_host():
    """Pass bad host to get_certificate_chain exception"""

    func_name: str = "get_certificate_chain"

    host = "nonexistenthost.com"
    port = 443

    with pytest.raises(Exception) as excinfo:
        get_certificate_chain(host, port)

    assert str(excinfo.value) == f"{func_name}: {host}:{port} is invalid or not known."


def test_get_cert_chain_host_timeout():
    """Pass bad port to get_certificate_chain to force the
    connection to time out"""

    func_name: str = "get_certificate_chain"

    host = "espn.com"
    port = 65534

    with pytest.raises(Exception) as excinfo:
        get_certificate_chain(host, port)

    assert str(excinfo.value) == f"{func_name}: Connection to {host}:{port} timed out."


def test_get_cert_chain_success():
    """Validate the issuer for microsoft.com with ms_pem"""

    host = "github.com"
    port = 443

    github = get_certificate_chain(host, port)

    assert github[1] == certs.github_issuer_pem


def test_get_cert_chain_bad_port():
    """Validate the issuer for microsoft.com with ms_pem"""

    host = "github.com"
    port = 80000

    func_name: str = "get_certificate_chain"

    with pytest.raises(Exception) as excinfo:
        get_certificate_chain(host, port)

    assert (
        str(excinfo.value)
        == f"{func_name}: Illegal port: {port}. Port must be between 0-65535."
    )


def test_invalid_certificate():
    """edellroot.badssl.com is invalid"""

    func_name: str = "get_certificate_chain"

    host = "edellroot.badssl.com"
    error = f"{func_name}: Certificate Verification failed for {host}."

    with pytest.raises(Exception) as excinfo:
        get_certificate_chain(host, 443)

    assert str(excinfo.value) == error


def test_extract_ocsp_url_success():
    """test a successful extract_ocsp_url function invocation"""

    host = "github.com"
    port = 443
    cert_chain = get_certificate_chain(host, port)
    ocsp_url = extract_ocsp_url(cert_chain)

    assert ocsp_url == "http://ocsp.digicert.com"


def test_build_ocsp_request_success():
    """test a successful build_ocsp_request function invocation"""

    host = "github.com"
    port = 443
    cert_chain = get_certificate_chain(host, port)
    ocsp_request_data = build_ocsp_request(cert_chain)

    assert ocsp_request_data == certs.github_ocsp_data


def test_build_ocsp_request_failure():
    """test an unsuccessful build_ocsp_request function invocation"""

    cert_chain = ["blah", "blah"]

    func_name: str = "build_ocsp_request"

    with pytest.raises(Exception) as excinfo:
        build_ocsp_request(cert_chain)

    assert str(excinfo.value) == f"{func_name}: Unable to load x509 certificate."


def test_get_ocsp_response_bad_url_format():
    """test an unsuccessful get_ocsp_response function invocation
    with a bad url format"""

    func_name: str = "get_ocsp_response"

    ocsp_url = "badurl"
    ocsp_request_data = b"dummydata"

    with pytest.raises(Exception) as excinfo:
        get_ocsp_response(ocsp_url, ocsp_request_data)

    assert str(excinfo.value) == f"{func_name}: URL failed validation for {ocsp_url}"


def test_get_ocsp_response_connection_error():
    """test an unsuccessful get_ocsp_response function invocation
    with a bad url input"""

    func_name: str = "get_ocsp_response"

    ocsp_url = "http://blahhhhhhhh.com"
    ocsp_request_data = b"dummydata"

    with pytest.raises(Exception) as excinfo:
        get_ocsp_response(ocsp_url, ocsp_request_data)

    assert str(excinfo.value) == f"{func_name}: {ocsp_url} is invalid or not known."


def test_get_ocsp_response_timeout():
    """test an unsuccessful get_ocsp_response function invocation
    with timeout"""

    func_name: str = "get_ocsp_response"

    ocsp_url = "http://blah.com:65534"
    ocsp_request_data = b"dummydata"

    with pytest.raises(Exception) as excinfo:
        get_ocsp_response(ocsp_url, ocsp_request_data)

    assert str(excinfo.value) == f"{func_name}: Request timeout for {ocsp_url}"


def test_extract_ocsp_result_unauthorized():
    """test an unsuccessful extract_ocsp_result function invocation"""

    func_name: str = "extract_ocsp_result"

    ocsp_response = get_ocsp_response(
        "http://ocsp.digicert.com", certs.unauthorized_ocsp_data
    )

    with pytest.raises(Exception) as excinfo:
        extract_ocsp_result(ocsp_response)

    assert str(excinfo.value) == f"{func_name}: OCSP Request Error: UNAUTHORIZED"


def test_extract_ocsp_result_success():
    """test an unsuccessful extract_ocsp_result function invocation"""

    cert_chain = get_certificate_chain("github.com", 443)
    ocsp_url = extract_ocsp_url(cert_chain)
    ocsp_request = build_ocsp_request(cert_chain)
    ocsp_response = get_ocsp_response(ocsp_url, ocsp_request)

    ocsp_result = extract_ocsp_result(ocsp_response)

    assert ocsp_result == "OCSP Status: GOOD"


def test_end_to_end_success_test():
    """test the full function end to end"""

    ocsp_result = get_ocsp_status("github.com", 443)

    assert ocsp_result == [
        "Host: github.com:443",
        "OCSP URL: http://ocsp.digicert.com",
        "OCSP Status: GOOD",
    ]


def test_end_to_end_test_bad_host():
    """test the full function end to end"""

    func_name: str = "get_certificate_chain"

    host = "nonexistenthost.com"
    ocsp_request = get_ocsp_status(host, 443)

    assert ocsp_request == [
        "Host: nonexistenthost.com:443",
        f"Error: {func_name}: nonexistenthost.com:443 is invalid or not known.",
    ]


def test_end_to_end_test_bad_fqdn():
    """test the full function end to end"""

    host = "nonexistentdomain"
    ocsp_request = get_ocsp_status(host, 443)

    assert ocsp_request == [
        "Host: nonexistentdomain:443",
        f"Error: {host} is not a valid FQDN.",
    ]


def test_end_to_end_test_host_timeout():
    """test the full function end to end"""

    func_name: str = "get_certificate_chain"

    host = "espn.com"
    ocsp_request = get_ocsp_status(host, 65534)

    assert ocsp_request == [
        "Host: espn.com:65534",
        f"Error: {func_name}: Connection to espn.com:65534 timed out.",
    ]


@pytest.mark.parametrize("root_ca", certs.cert_authorities)
def test_a_cert_from_each_root_ca(root_ca):
    """Test a cert from each root CA to ensure test coverage"""

    try:
        ocsp_request = get_ocsp_status(root_ca, 443)

    except Exception as err:
        raise err

    assert ocsp_request[2] == "OCSP Status: GOOD"


def test_bad_port_overflow():
    """Validate passing a bad port results in failure"""

    host = "espn.com"
    ocsp_request = get_ocsp_status(host, 80000)

    assert ocsp_request == [
        "Host: espn.com:80000",
        "Error: Invalid port: '80000'. Port must be between 0-65535.",
    ]


def test_bad_port_typeerror():
    """Validate passing a bad port results in failure"""

    host = "espn.com"
    ocsp_request = get_ocsp_status(host, "a")  # type: ignore

    assert ocsp_request == [
        "Host: espn.com:a",
        "Error: Invalid port: 'a'. Port must be between 0-65535.",
    ]


def test_no_port_supplied():
    """Validate that when no port is supplied, the default of 443 is used"""

    host = "github.com"
    ocsp_request = get_ocsp_status(host)

    assert ocsp_request == [
        "Host: github.com:443",
        "OCSP URL: http://ocsp.digicert.com",
        "OCSP Status: GOOD",
    ]


def test_strip_http_from_host():
    """Validate stripping http from host"""

    host = "http://github.com"
    ocsp_request = get_ocsp_status(host, 443)

    assert ocsp_request == [
        "Host: http://github.com:443",
        "OCSP URL: http://ocsp.digicert.com",
        "OCSP Status: GOOD",
    ]


def test_strip_https_from_host():
    """Validate stripping https from host"""

    host = "https://github.com"
    ocsp_request = get_ocsp_status(host, 443)

    assert ocsp_request == [
        "Host: https://github.com:443",
        "OCSP URL: http://ocsp.digicert.com",
        "OCSP Status: GOOD",
    ]


def test_tls_fatal_alert_112():
    """Validate Unrecognized server name provided"""

    host = "nginx.net"
    func_name: str = "get_certificate_chain"

    with pytest.raises(Exception) as excinfo:
        get_certificate_chain(host, 443)

    assert (
        str(excinfo.value)
        == f"{func_name}: Unrecognized server name provided. Check your target and try again."
    )


def test_tls_fatal_alert_50():
    """Validate SSL/TLS Decode Error"""

    host = "pattern-wiki.org"
    func_name: str = "get_certificate_chain"

    with pytest.raises(Exception) as excinfo:
        get_certificate_chain(host, 443)

    assert (
        str(excinfo.value)
        == f"{func_name}: Decode Error. Check your target and try again."
    )
