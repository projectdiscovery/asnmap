FROM alpine:3.24.1

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="Go CLI and Library for quickly mapping organization network ranges using ASN information."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="asnmap"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/asnmap"

RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/asnmap /usr/local/bin/

ENTRYPOINT ["asnmap"]
