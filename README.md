# OCSP-Requester

## Overview

OCSP-Requester is a python package based on Alban Diquet's [nassl](https://github.com/nabla-c0d3/nassl) wrapper and the Python Cryptographic Authority's [cryptography](https://github.com/pyca/cryptography) package. Relying on a web browser to check the revocation status of a x509 digital certificate [has](https://www.imperialviolet.org/2014/04/19/revchecking.html) [been](https://www.imperialviolet.org/2014/04/29/revocationagain.html) [broken](https://scotthelme.co.uk/revocation-is-broken/) from the beginning, and validating certificates outside of the web browser is a manual process. OCSP-Requester aims to solve this by providing an automated means to check the [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) revocation status for a x509 digital certificate.


## Pre-requisites

__Python__ - Python 3.7 (64-bit) and above.


## Installation

```pip install ocsp-checker```


## Usage

```
>>> from ocspchecker import ocspchecker
>>> ocsp_request = ocspchecker.get_ocsp_status("github.com")
```

## Sample Output

Sample output below, let me know if you want to add more fields/information to the output.

```
['Host: github.com:443', 'OCSP URL: http://ocsp.digicert.com', 'OCSP Status: GOOD']
```

PLEASE NOTE: If you run this on a network with a MITM SSL proxy, you may receive unintended results (see below):
```
["Error: Certificate Authority Information Access (AIA) Extension Missing. Possible MITM Proxy."]
```

## Feedback

Send me mail at joe@metlife.com