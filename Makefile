export PATH := $(CURDIR)/bin:$(PATH)
export SHELL := bash

include ./.misc/make/tools.Makefile
include ./.misc/make/help.Makefile

# ~~~ Development ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.PHONY: deps
deps: bin/golangci-lint bin/gotestsum ## Install pinned dev tools into ./bin

PKG ?= ./...

.PHONY: fmt
fmt: ## Format with gofmt, gofumpt, goimports
	@go fmt ./...
	@go run mvdan.cc/gofumpt@v0.9.2 -l -w .
	@go run golang.org/x/tools/cmd/goimports@v0.39.0 -local github.com/basaltdbhq/basaltdb -w .

.PHONY: lint
lint: deps ## Run golangci-lint (includes formatters check and a config check)
	@$(GOLANGCI) config verify -c .golangci.yml
	@$(GOLANGCI) run -c .golangci.yml ./...

.PHONY: vet
vet: ## go vet
	@go vet ./...

.PHONY: test
test: bin/gotestsum portal-build ## Race tests (gotestsum; builds dist/portal first so TestPortalBuildMatchesEmbed never skips)
	@$(GOTESTSUM) --format pkgname-and-test-fails --hide-summary=skipped -- -race -count=1 -timeout 15m $(PKG)

.PHONY: test-cover
test-cover: bin/gotestsum ## Tests with coverage.out
	@$(GOTESTSUM) --format pkgname -- -race -count=1 -timeout 15m -coverprofile=coverage.out -covermode=atomic $(PKG)
	@go tool cover -func=coverage.out | tail -1

VERSION ?= $(shell git describe --tags --always --match 'v*' 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/basaltdbhq/basaltdb/internal/buildinfo.Version=$(VERSION)

.PHONY: build
build: ## Build the static basalt binary (CGO_ENABLED=0)
	@CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/basalt ./cmd/basalt

.PHONY: mocks
mocks: bin/mockery ## Regenerate mocks from .mockery.yml
	@$(MOCKERY) --config .mockery.yml

.PHONY: install-sh-check
install-sh-check: ## POSIX syntax, default repo, and archive names for install.sh
	@sh -n install.sh
	@sh -n scripts/release-archive-smoke.sh
	@sh -n scripts/release-kind.sh
	@sh -n scripts/require-v-tag.sh
	@sh scripts/release-kind_test.sh
	@grep -Fq 'tags: ["v*"]' .github/workflows/release.yml
	@if grep -E '^[[:space:]]*(branches|workflow_dispatch):' .github/workflows/release.yml; then echo 'release.yml must not trigger on branches or workflow_dispatch' >&2; exit 1; fi
	@sh install.sh --print-platform >/dev/null
	@grep -q 'BASALTDB_REPO="$${BASALTDB_REPO:-BasaltDBHq/BasaltDB}"' install.sh
	@grep -Fq 'name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"' .goreleaser.yaml
	@grep -Fq 'goos: [linux, darwin, windows]' .goreleaser.yaml
	@grep -Fq 'goarch: [amd64, arm64]' .goreleaser.yaml
	@plat=$$(sh install.sh --print-platform); \
	got=$$(sh install.sh --print-archive-name v0.0.1-alpha); \
	want="basaltdb_0.0.1-alpha_$${plat}.tar.gz"; \
	test "$$got" = "$$want"

.PHONY: npm-check
npm-check: ## Syntax-check the npm shim, MCP registry and publish scripts
	@node --check npm/cli/lib/binary.js
	@node --check npm/cli/bin/basalt.js
	@node -e "require('./npm/cli/lib/binary').platformKey()"
	@sh -n scripts/npm-publish.sh
	@sh -n scripts/mcp-registry-publish.sh
	@NPM_TOKEN= sh scripts/npm-publish.sh | grep -q 'skipping npm publish'
	@MCP_REGISTRY_TOKEN= sh scripts/mcp-registry-publish.sh | grep -q 'skipping MCP registry'
	@if NPM_TOKEN=x sh scripts/npm-publish.sh nightly; then echo 'npm-publish must refuse nightly' >&2; exit 1; fi
	@if MCP_REGISTRY_TOKEN=x sh scripts/mcp-registry-publish.sh nightly; then echo 'mcp-registry-publish must refuse nightly' >&2; exit 1; fi

.PHONY: web-check
web-check: ## Syntax-check the approval and revert pages and run their codec tests against the Go fixtures
	@for f in web/lib/*.js; do node --check "$$f" || exit 1; done
	@node --test web/lib/*.test.mjs >/dev/null || node --test web/lib/*.test.mjs

# The portal's static host serves only the files the engine's embed serves
# (web/embed.go), plus the Pages config. Tests and Go files stay out.
PORTAL_DIR ?= dist/portal

.PHONY: portal-build
portal-build: ## Copy only the served portal files to dist/portal (Cloudflare Pages output)
	@rm -rf "$(PORTAL_DIR)"
	@mkdir -p "$(PORTAL_DIR)/lib" "$(PORTAL_DIR)/fonts"
	@for d in approve revert register passkeys; do mkdir -p "$(PORTAL_DIR)/$$d" && cp "web/$$d/index.html" "$(PORTAL_DIR)/$$d/index.html" || exit 1; done
	@for f in web/lib/*.js; do cp "$$f" "$(PORTAL_DIR)/lib/" || exit 1; done
	@cp web/fonts/*.woff2 web/fonts/OFL.txt "$(PORTAL_DIR)/fonts/"
	@cp web/style.css web/_headers web/_redirects "$(PORTAL_DIR)/"
	@if find "$(PORTAL_DIR)" \( -name '*.test.mjs' -o -name '*.go' \) | grep -q .; then echo 'portal-build: test or Go files in output' >&2; exit 1; fi

.PHONY: ci
ci: lint vet install-sh-check npm-check web-check portal-build test ## Same steps as the GitHub check job
