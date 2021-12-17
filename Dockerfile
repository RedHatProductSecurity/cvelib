FROM quay.io/fedora/fedora:latest

RUN dnf --nodocs -y install python3-pip && \
    pip3 install --no-cache-dir cvelib

ENTRYPOINT ["cve"]
