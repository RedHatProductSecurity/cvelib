FROM quay.io/fedora/fedora:latest

LABEL maintainer="Red Hat Product Security Dev - Red Hat, Inc." \
      vendor="Red Hat Product Security Dev - Red Hat, Inc." \
      summary="Container image for the cvelib CLI utility." \
      distribution-scope="public"

RUN dnf --nodocs -y install python3-pip && dnf clean

RUN pip3 install --no-cache-dir cvelib

ENTRYPOINT ["cve"]
