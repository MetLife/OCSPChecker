""" A full cert chain is required to make a proper OCSP request. However,
 the ssl module for python 3.x does not support the get_peer_cert_chain()
 method. get_peer_cert_chain() is in flight: https://github.com/python/cpython/pull/17938

 For a short-term fix, I will use nassl to grab the full cert chain. """

from socket import AF_INET, gaierror, socket, SOCK_STREAM, timeout
from typing import Any, List
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509 import ExtensionOID, ExtensionNotFound, ocsp
from nassl.ssl_client import OpenSslVersionEnum, OpenSslVerifyEnum, SslClient
from nassl._nassl import OpenSSLError, WantReadError, WantX509LookupError
import requests
from validators import domain, url


def get_ocsp_status(host: str, port: Any = None) -> list:
    """ Main function with two inputs: host, and port.
    Port defaults to TCP 443 """

    results = []
    results.append(f"Host: {host}:{port}")

    # pylint: disable=W0703
    # All of the exceptions in this function are passed-through

    # Validate port
    if port is None:
        port = 443
    else:
        try:
            port = verify_port(port)

        except Exception as err:
            results.append("Error: " + str(err))
            return results

    # Sanitize host
    try:
        host = verify_host(host)

    except Exception as err:
        results.append("Error: " + str(err))
        return results

    try:
        cert_chain = get_certificate_chain(host, port)

    except Exception as err:
        results.append("Error: " + str(err))
        return results

    try:
        ocsp_url = extract_ocsp_url(cert_chain)

    except Exception as err:
        results.append("Error: " + str(err))
        return results

    try:
        ocsp_request = build_ocsp_request(cert_chain)

    except Exception as err:
        results.append("Error: " + str(err))
        return results

    try:
        ocsp_response = get_ocsp_response(ocsp_url, ocsp_request)

    except Exception as err:
        results.append("Error: " + str(err))
        return results

    try:
        ocsp_result = extract_ocsp_result(ocsp_response)

    except Exception as err:
        results.append("Error: " + str(err))
        return results

    results.append(f"OCSP URL: {ocsp_url}")
    results.append(f"{ocsp_result}")

    return results


def get_certificate_chain(host: str, port: int) -> List[str]:

    """ Connect to the host on the port and obtain certificate chain.
     TODO: Tests against WantReadError and WantX509LookupError needed. """

    cert_chain = []

    soc = socket(AF_INET, SOCK_STREAM, proto=0)
    soc.settimeout(3)

    try:
        soc.connect((host, port))

    except gaierror:
        raise Exception(f"{host}:{port} is invalid or not known.") from None

    except timeout:
        raise Exception(f"Connection to {host}:{port} timed out.") from None

    except OverflowError:
        raise Exception(f"Illegal port: {port}. Port must be between 0-65535.") from None

    except TypeError:
        raise Exception(f"Illegal port: {port}. Port must be between 0-65535.") from None

    ssl_client = SslClient(
        ssl_version=OpenSslVersionEnum.SSLV23,
        underlying_socket=soc,
        ssl_verify=OpenSslVerifyEnum.NONE
    )

    # Add Server Name Indication (SNI) extension to the CLIENT HELLO
    ssl_client.set_tlsext_host_name(host)

    try:
        ssl_client.do_handshake()
        cert_chain = ssl_client.get_received_chain()

    except WantReadError as err:
        raise ValueError(err.strerror) from None

    except WantX509LookupError as err:
        raise ValueError(err.strerror) from None

    except OpenSSLError as err:
        raise ValueError(err) from None

    finally:
        ssl_client.shutdown()
        soc = None

    return cert_chain


def extract_ocsp_url(cert_chain: List[str]) -> str:

    """ Parse the leaf certificate and extract the access method and
     access location AUTHORITY_INFORMATION_ACCESS extensions to
     get the ocsp url """

    ocsp_url = ""

    # Convert to a certificate object in cryptography.io
    certificate = x509.load_pem_x509_certificate(
        str.encode(cert_chain[0]), default_backend()
    )

    # Check to ensure it has an AIA extension
    try:
        aia_extensions = certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value

        # pylint: disable=C0200, W0212
        for index, value in enumerate(aia_extensions):
            if aia_extensions[index].access_method._name == "OCSP":
                ocsp_url = aia_extensions[index].access_location.value

    except ExtensionNotFound:
        raise ValueError(
            "Certificate Authority Information Access (AIA) Extension Missing. Possible MITM Proxy."
        ) from None

    return ocsp_url


def build_ocsp_request(cert_chain: List[str]) -> bytes:

    """ Build an OCSP request out of the leaf and issuer pem certificates
     see: https://cryptography.io/en/latest/x509/ocsp/#cryptography.x509.ocsp.OCSPRequestBuilder
     for more information """

    try:
        leaf_cert = x509.load_pem_x509_certificate(
            str.encode(cert_chain[0]), default_backend()
        )
        issuer_cert = x509.load_pem_x509_certificate(
            str.encode(cert_chain[1]), default_backend()
        )

    except ValueError:
        raise Exception("Unable to load x509 certificate.") from None

    # Build OCSP request
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(leaf_cert, issuer_cert, SHA1())
    ocsp_data = builder.build()
    ocsp_request_data = ocsp_data.public_bytes(serialization.Encoding.DER)

    return ocsp_request_data


def get_ocsp_response(ocsp_url: str, ocsp_request_data: bytes):

    """ Send OCSP request to ocsp responder and retrieve response """

    # Confirm that the ocsp_url is a valid url
    if not url(ocsp_url):
        raise Exception(f"URL failed validation for {ocsp_url}")

    try:
        ocsp_response = requests.post(
            ocsp_url,
            headers={"Content-Type": "application/ocsp-request"},
            data=ocsp_request_data,
            timeout=5,
        )

    except requests.exceptions.Timeout:
        raise Exception(f"Request timeout for {ocsp_url}") from None

    except requests.exceptions.ConnectionError:
        raise Exception(f"Unknown Connection Error to {ocsp_url}") from None

    except requests.exceptions.RequestException:
        raise Exception(f"Unknown Connection Error to {ocsp_url}") from None

    return ocsp_response


def extract_ocsp_result(ocsp_response):

    """ Extract the OCSP result from the provided ocsp_response """

    try:
        ocsp_response = ocsp.load_der_ocsp_response(ocsp_response.content)
        # OCSP Response Status here:
        # https://cryptography.io/en/latest/_modules/cryptography/x509/ocsp/#OCSPResponseStatus
        # A status of 0 == OCSPResponseStatus.SUCCESSFUL
        if str(ocsp_response.response_status.value) != "0":
            # This will return one of five errors, which means connecting
            # to the OCSP Responder failed for one of the below reasons:
            # MALFORMED_REQUEST = 1
            # INTERNAL_ERROR = 2
            # TRY_LATER = 3
            # SIG_REQUIRED = 5
            # UNAUTHORIZED = 6
            ocsp_response = str(ocsp_response.response_status)
            ocsp_response = ocsp_response.split(".")
            raise Exception(f"OCSP Request Error: {ocsp_response[1]}")

        certificate_status = str(ocsp_response.certificate_status)
        certificate_status = certificate_status.split(".")
        return f"OCSP Status: {certificate_status[1]}"

    except ValueError as err:
        return f"{str(err)}"


def verify_port(port: Any) -> int:
    """ Check port for type and validity """

    if not isinstance(port, int):
        if port.isnumeric() is False:
            raise Exception(f"Invalid port: '{port}'. Port must be between 0-65535.")

    _port = int(port)

    if _port > 65535 or _port == 0:
        raise Exception(f"Invalid port: '{port}'. Port must be between 0-65535.")

    return _port


def verify_host(host: str) -> str:
    """ Parse a DNS name to ensure it does not contain http(s) """
    parsed_name = urlparse(host)

    # The below parses out http(s) from a name
    host_candidate = parsed_name.netloc
    if host_candidate == "":
        host_candidate = parsed_name.path

    # The below ensures a valid domain was supplied
    if not domain(host_candidate):
        raise Exception("Invalid FQDN", f"{host} is not a valid FQDN")

    return host_candidate
