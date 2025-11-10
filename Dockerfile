# Base
FROM golang:1.25.4-alpine AS builder

RUN apk add --no-cache git build-base gcc musl-dev
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build ./cmd/asnmap

FROM alpine:3.22.2
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /app/asnmap /usr/local/bin/

ENTRYPOINT ["asnmap"]
