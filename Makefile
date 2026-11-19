# Build and check uBixGate. CI runs the same targets.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/ubixsys/ubixgate/internal/version.Version=$(VERSION)
TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

# Go packages we own. test/ holds the integration tests.
GO_PKGS := ./...
GO_DIRS := cmd internal test examples

# The linter is a tool, not a module dependency: it is not in go.mod. A golangci-lint on
# PATH is used when present; otherwise the pinned version is built with `go run`.
GOLANGCI_LINT_VERSION := v2.15.0
GOLANGCI_LINT ?= $(shell command -v golangci-lint 2>/dev/null || echo go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION))

# The whole codebase should be readable in an afternoon: non-test Go under cmd/ and
# internal/ stays under this many lines. Raising it is a decision, not a fix.
SIZE_BUDGET := 4000

.PHONY: build test lint fmt-check vet prose-check size-check script-check check cross dist release-notes loc clean

build:
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o bin/ubixgate ./cmd/ubixgate

test:
	go test -race $(GO_PKGS)

# The gate: formatting, vet, lint, prose style, size budget, script tests, unit and
# integration tests. GitLab's go-check job and GitHub's CI run exactly this.
check: fmt-check vet lint prose-check size-check script-check test

fmt-check:
	@dirs=$$(ls -d $(GO_DIRS) 2>/dev/null); \
	out=$$(gofmt -l $$dirs); \
	test -z "$$out" || { echo "gofmt needed:"; echo "$$out"; exit 1; }

vet:
	go vet $(GO_PKGS)

lint:
	$(GOLANGCI_LINT) run $(GO_PKGS)

# House style: no em dashes or en dashes anywhere in tracked text (docs, comments,
# commit-facing files). The characters are written as octal so this file passes too.
prose-check:
	@hits=$$(git ls-files -z | xargs -0 grep -nI -e "$$(printf '\342\200\224')" -e "$$(printf '\342\200\223')" 2>/dev/null | cut -d: -f1,2); \
	if [ -n "$$hits" ]; then echo "Em or en dash found (file:line); restructure the sentence:"; echo "$$hits"; exit 1; fi

size-check:
	@n=$$(find cmd internal -name '*.go' ! -name '*_test.go' -exec cat {} + | wc -l | tr -d ' '); \
	echo "non-test Go: $$n lines (budget $(SIZE_BUDGET))"; \
	test $$n -le $(SIZE_BUDGET) || { echo "over the size budget"; exit 1; }

loc:
	@find cmd internal -name '*.go' ! -name '*_test.go' | xargs wc -l | sort -n

script-check:
	@bash bin/promote_test.sh >/dev/null || { bash bin/promote_test.sh; exit 1; }
	@echo "promote.sh tests pass."

cross:
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "build $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags '$(LDFLAGS)' \
			-o dist/ubixgate-$$os-$$arch$$ext ./cmd/ubixgate || exit 1; \
	done

# Release archives from the cross builds: one per target, each holding the binary, LICENSE
# and README.md (.tar.gz, or .zip for Windows), and SHA256SUMS over them. The release
# workflow runs this; run it locally to see exactly what a release would publish.
dist: cross
	@rm -rf dist/pkg dist/*.tar.gz dist/*.zip dist/SHA256SUMS
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		name=ubixgate-$(VERSION)-$$os-$$arch; \
		mkdir -p dist/pkg/$$name && \
		cp dist/ubixgate-$$os-$$arch$$ext dist/pkg/$$name/ubixgate$$ext && \
		cp LICENSE README.md dist/pkg/$$name/ || exit 1; \
		if [ $$os = windows ]; then \
			(cd dist/pkg && zip -qr ../$$name.zip $$name) || exit 1; \
		else \
			COPYFILE_DISABLE=1 tar -C dist/pkg -czf dist/$$name.tar.gz $$name || exit 1; \
		fi; \
		echo "package dist/$$name"; \
	done
	@rm -rf dist/pkg
	@cd dist && if command -v sha256sum >/dev/null; then sum='sha256sum'; else sum='shasum -a 256'; fi && \
		$$sum *.tar.gz *.zip > SHA256SUMS
	@echo "wrote dist/SHA256SUMS"

# Print the CHANGELOG section for VERSION (v0.1.0 reads "## [0.1.0]"), or fail if there
# is none. The release workflow uses it for the release notes.
release-notes:
	@awk -v v="$(patsubst v%,%,$(VERSION))" ' \
		index($$0, "## [" v "]") == 1 { found = 1; next } \
		found && /^## \[/ { exit } \
		found { print } \
		END { if (!found) { print "CHANGELOG.md has no section for " v > "/dev/stderr"; exit 1 } }' CHANGELOG.md

clean:
	rm -rf bin/ubixgate dist
