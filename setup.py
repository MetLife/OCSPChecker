""" Setup file based on https://github.com/pypa/sampleproject/blob/master/setup.py """

import pathlib

from setuptools import find_packages, setup

here = pathlib.Path(__file__).parent.resolve()
long_description = (here / "README.md").read_text(encoding="utf-8")

setup(
    name="ocsp-checker",
    version="1.9.7",
    description="Library used to check the OCSP revocation status for a x509 digital certificate.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/MetLife/OCSPChecker",
    author="Joe Gatt",
    author_email="gattjoseph@hotmail.com",
    license="Apache 2.0",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    project_urls={
        "Source": "https://github.com/MetLife/OCSPChecker",
        "Changelog": "https://github.com/MetLife/OCSPChecker/blob/master/CHANGELOG.md",
        "Documentation": "https://github.com/MetLife/OCSPChecker/blob/master/README.md",
    },
    keywords="ssl, tls, ocsp, python, security",
    packages=find_packages(include=["ocspchecker"]),
    entry_points={"console_scripts": ["ocspchecker = ocspchecker.__main__:main"]},
    # Dependencies
    install_requires=["cryptography>=36.0", "nassl>=4.0", "validators>=0.18"],
)
