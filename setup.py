""" Setup file based on https://github.com/pypa/sampleproject/blob/master/setup.py """

from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()
long_description = (here / 'README.md').read_text(encoding='utf-8')

setup(
    name="ocsp-checker",
    version="1.3.0",
    description="Library used to check the OCSP revocation status for a x509 digital certificate.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/MetLife/OCSPChecker",
    author="Joe Gatt",
    author_email="joe@metlife.com",
    license="MIT",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    project_urls={
        "Source": "https://github.com/MetLife/OCSPChecker",
        "Changelog": "https://github.com/MetLife/OCSPChecker/blob/master/CHANGELOG.md"
    },
    keywords="ssl, tls, ocsp, python, security",
    packages=find_packages(include=["ocspchecker"]),
    # Dependencies
    install_requires=[
        "cryptography==2.9.2",
        "nassl==3.0.0",
        "requests>=2.24",
        "validators==0.16.0"
        ],
)