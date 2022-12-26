##
##Build
##
FROM golang:1.19.4 AS builder

WORKDIR /asnmap

COPY go.mod go.sum cmd . ./

RUN go build -o "asnmap" ./cmd/asnmap/

#
#Deploy
#
FROM alpine:3.16.3

RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2 && \
    apk update && \
    apk add ca-certificates wget && \
    apk add ca-certificates && \
    rm -rf /var/cache/apk/* && \
    wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.30-r0/glibc-2.30-r0.apk && \
    apk --no-cache add glibc-2.30-r0.apk

COPY --from=builder /libs/asnmap .

ENTRYPOINT [ "./asnmap" ]
