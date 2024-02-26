# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v
# This should be disabled if the binary uses pprof
LDFLAGS := -s -w

ifneq ($(shell go env GOOS),darwin)
LDFLAGS := -extldflags "-static"
endif
    

.PHONY: cli test tidy

cli, build:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "asnmap" ./cmd/asnmap/
test:
	$(GOCLEAN) -testcache
	$(GOTEST) -v ./...
tidy:
	$(GOMOD) tidy
