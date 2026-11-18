ifeq ($(ARCH),x86_64)
	ARCH := amd64
else ifeq ($(ARCH),aarch64)
	ARCH := arm64
endif

define github_url
    https://github.com/$(GITHUB)/releases/download/v$(VERSION)/$(ARCHIVE)
endef

bin:
	@ mkdir -p $@

GOLANGCI := $(shell command -v golangci-lint 2>/dev/null || echo "$(CURDIR)/bin/golangci-lint")
GOTESTSUM := $(shell command -v gotestsum 2>/dev/null || echo "$(CURDIR)/bin/gotestsum")
MOCKERY := $(shell command -v mockery 2>/dev/null || echo "$(CURDIR)/bin/mockery")
REDOCLY_VERSION := 1.34.3
ASYNCAPI_CLI_VERSION := 2.13.0
NPM := $(shell command -v npm 2>/dev/null)

bin/golangci-lint: VERSION := v2.15.0
bin/golangci-lint: bin
	@ printf "Install golangci-lint... "
	@ GOBIN=$(CURDIR)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(VERSION)
	@ echo "done."

bin/gotestsum: VERSION := v1.13.0
bin/gotestsum: bin
	@ printf "Install gotestsum... "
	@ GOBIN=$(CURDIR)/bin go install gotest.tools/gotestsum@$(VERSION)
	@ echo "done."

bin/mockery: VERSION := 3.7.0
bin/mockery: bin
	@ printf "Install mockery... "
	@ MOCK_OS=$$(uname -s); MOCK_ARCH=$$(uname -m); \
		ASSET="mockery_$(VERSION)_$${MOCK_OS}_$${MOCK_ARCH}.tar.gz"; \
		curl -fsSL "https://github.com/vektra/mockery/releases/download/v$(VERSION)/$${ASSET}" \
			| tar -zOxf - mockery > $@ && chmod +x $@
	@ echo "done."

# The protobuf plugins come at the versions go.mod requires, so the generated
# code follows the module's own protobuf and connect versions.
bin/protoc-gen-go: bin go.mod
	@ GOBIN=$(CURDIR)/bin go install google.golang.org/protobuf/cmd/protoc-gen-go

bin/protoc-gen-connect-go: bin go.mod
	@ GOBIN=$(CURDIR)/bin go install connectrpc.com/connect/cmd/protoc-gen-connect-go
