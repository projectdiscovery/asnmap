# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean

.PHONY: cli test tidy

cli:
	$(GOBUILD) -v -ldflags="-extldflags=-static" -o "asnmap" ./cmd/asnmap/
test:
	$(GOCLEAN) -testcache
	$(GOTEST) -v ./...
tidy:
	$(GOMOD) tidy
