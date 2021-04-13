# Changelog for OCSP-StatusChecker

# v1.0.0
- Initial Release

# v1.3.0
- Add Server Name Indication (SNI) support
- Add tests to cover each root certificate authority in use
- Fix MITM proxy error reporting

# v1.4.0
- Added the ability to call from the command line
- Updated cryptography and validators
- Some pylint fixes

# v1.5.0
- Fixed an uncaught exception when port is > 65535 or not numeric
- Parse out http(s) when submitting a request

# v1.6.0
- Upgrade cryptography to 3.2
- Upgrade nassl to 3.1
- Added tox tests for Python versions 3.7 and 3.8

# v1.7.0
- Added support for M1 Mac's
- Added support for Python 3.9
- Upgraded nassl to 4.0.0
- Upgraded cryptography to 3.4.6
- Fixed failing tests
- Added tox tests for Python 3.9

# v1.8.0
- Fixed a bug to handle a situation when parsing a certificate with an AIA extension but no OCSP URL
- Fixed a bug to handle a situation where the remote host is not using SSL/TLS and we attempt to do a SSL/TLS handshake
- Fixed a bug to handle a situation where the remote host does not respond to a Client Hello
- Prepended all exceptions with the function name for easier troubleshooting
- Upgraded cryptography to 3.4.7 to support the latest versions of OpenSSL
