# Pinning apk package versions breaks the build once Alpine drops them; the base image tag is the pin.
# hadolint global ignore=DL3018
# Base
FROM golang:1.26.10-alpine AS builder

RUN apk add --no-cache git build-base gcc musl-dev
WORKDIR /app
COPY . /app
RUN go mod download && go build ./cmd/asnmap

FROM alpine:3.24
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /app/asnmap /usr/local/bin/

ENTRYPOINT ["asnmap"]
