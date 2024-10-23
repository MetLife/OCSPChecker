# Usually you do not have to specify amd64, but on an Apple M1 you do if you want to use packages
# that are not optimized for arm64 like NaSSL
FROM --platform=amd64 python:3.12.7-slim-bullseye

SHELL ["/bin/bash", "--login", "-c"]

ENV DEBIAN_FRONTEND noninteractive
ENV LANG C.UTF-8

RUN useradd -m ocspdev

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    netbase \
    curl \
    git \
    bash-completion \
    && rm -rf /var/lib/apt/lists/*

USER ocspdev
WORKDIR /home/ocspdev

# Copy OcspChecker Folder
COPY --chown=ocspdev:ocspdev . /home/ocspdev/OcspChecker/

CMD [ "bash" ]
