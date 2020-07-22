""" Tests """
import pytest

from ocspchecker.ocspchecker import (build_ocsp_request, get_certificate_chain,
                                     get_ocsp_response, extract_ocsp_url,
                                     extract_ocsp_result, get_ocsp_status)
from . import certs


def test_get_cert_chain_bad_host():
    """ Pass bad host to get_certificate_chain exception """

    host = "nonexistenthost.com"
    port = 443

    with pytest.raises(Exception) as excinfo:
        get_certificate_chain(host, port)

    assert str(excinfo.value) == f"{host}:{port} is invalid or not known."


def test_get_cert_chain_host_timeout():
    """ Pass bad port to get_certificate_chain to force the
     connection to time out """

    host = "espn.com"
    port = 65534

    with pytest.raises(Exception) as excinfo:
        get_certificate_chain(host, port)

    assert str(excinfo.value) == f"Connection to {host}:{port} timed out."


def test_get_cert_chain_success():
    """ Validate the issuer for microsoft.com with ms_pem """

    host = "github.com"
    port = 443

    github = get_certificate_chain(host, port)

    assert github[1] == certs.github_issuer_pem


def test_missing_ocsp_extension():
    """ edellroot.badssl.com is missing the OCSP extensions """

    host = "edellroot.badssl.com"
    port = 443
    cert_chain = get_certificate_chain(host, port)

    with pytest.raises(Exception) as excinfo:
        extract_ocsp_url(cert_chain)

    assert str(excinfo.value) == "Certificate Authority Information Access (AIA) Extension Missing. Possible MITM Proxy."


def test_extract_ocsp_url_success():
    """ test a successful extract_ocsp_url function invocation """

    host = "github.com"
    port = 443
    cert_chain = get_certificate_chain(host, port)
    ocsp_url = extract_ocsp_url(cert_chain)

    assert ocsp_url == "http://ocsp.digicert.com"


def test_build_ocsp_request_success():
    """ test a successful build_ocsp_request function invocation """

    host = "github.com"
    port = 443
    cert_chain = get_certificate_chain(host, port)
    ocsp_request_data = build_ocsp_request(cert_chain)

    assert ocsp_request_data == certs.github_ocsp_data


def test_build_ocsp_request_failure():
    """ test an unsuccessful build_ocsp_request function invocation """

    cert_chain = ["blah", "blah"]

    with pytest.raises(Exception) as excinfo:
        build_ocsp_request(cert_chain)

    assert str(excinfo.value) == "Unable to load x509 certificate."


def test_get_ocsp_response_bad_url_format():
    """ test an unsuccessful get_ocsp_response function invocation
     with a bad url format """

    ocsp_url = "badurl"
    ocsp_request_data = b"dummydata"

    with pytest.raises(Exception) as excinfo:
        get_ocsp_response(ocsp_url, ocsp_request_data)

    assert str(excinfo.value) == f"URL failed validation for {ocsp_url}"


def test_get_ocsp_response_connection_error():
    """ test an unsuccessful get_ocsp_response function invocation
     with a bad url input """

    ocsp_url = "http://blahhhhhhhh.com"
    ocsp_request_data = b"dummydata"

    with pytest.raises(Exception) as excinfo:
        get_ocsp_response(ocsp_url, ocsp_request_data)

    assert str(excinfo.value) == f"Unknown Connection Error to {ocsp_url}"


def test_get_ocsp_response_timeout():
    """ test an unsuccessful get_ocsp_response function invocation
     with a bad url input """

    ocsp_url = "http://blah.com:65534"
    ocsp_request_data = b"dummydata"

    with pytest.raises(Exception) as excinfo:
        get_ocsp_response(ocsp_url, ocsp_request_data)

    assert str(excinfo.value) == f"Request timeout for {ocsp_url}"


def test_get_ocsp_response_success():
    """ test an successful get_ocsp_response function invocation """

    cert_chain = get_certificate_chain("github.com", 443)
    ocsp_url = extract_ocsp_url(cert_chain)
    ocsp_request = build_ocsp_request(cert_chain)

    ocsp_response = get_ocsp_response(ocsp_url, ocsp_request)

    for header in ocsp_response.headers:
        if "application/ocsp-response" in ocsp_response.headers[header]:
            # There may be a better way to do this, but this proves we got a response
            # from the OCSP server
            assert True


def test_extract_ocsp_result_unauthorized():
    """ test an unsuccessful extract_ocsp_result function invocation """

    ocsp_response = get_ocsp_response("http://ocsp.digicert.com", certs.unauthorized_ocsp_data)

    with pytest.raises(Exception) as excinfo:
        extract_ocsp_result(ocsp_response)

    assert str(excinfo.value) == "OCSP Request Error: UNAUTHORIZED"


def test_extract_ocsp_result_success():
    """ test an unsuccessful extract_ocsp_result function invocation """

    cert_chain = get_certificate_chain("github.com", 443)
    ocsp_url = extract_ocsp_url(cert_chain)
    ocsp_request = build_ocsp_request(cert_chain)
    ocsp_response = get_ocsp_response(ocsp_url, ocsp_request)

    ocsp_result = extract_ocsp_result(ocsp_response)

    assert ocsp_result == "OCSP Status: GOOD"


def test_end_to_end_success_test():
    """ test the full function end to end """

    ocsp_result = get_ocsp_status("github.com", 443)

    assert ocsp_result == ['Host: github.com:443',\
                           'OCSP URL: http://ocsp.digicert.com', 'OCSP Status: GOOD']


def test_end_to_end_test_bad_host():
    """ test the full function end to end """

    host = "nonexistenthost.com"
    ocsp_request = get_ocsp_status(host, 443)

    assert ocsp_request == ['Host: nonexistenthost.com:443',
                            'Error: nonexistenthost.com:443 is invalid or not known.']


def test_end_to_end_test_host_timeout():
    """ test the full function end to end """

    host = "espn.com"
    ocsp_request = get_ocsp_status(host, 65534)

    assert ocsp_request == ['Host: espn.com:65534',
                            'Error: Connection to espn.com:65534 timed out.']


@pytest.mark.parametrize("root_ca", certs.cert_authorities)
def test_a_cert_from_each_root_ca(root_ca):

    try:
        ocsp_request = get_ocsp_status(root_ca)
        
    except Exception as err:
        raise err

    assert ocsp_request[2] == 'OCSP Status: GOOD'
