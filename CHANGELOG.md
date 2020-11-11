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
