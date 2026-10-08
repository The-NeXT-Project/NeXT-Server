.PHONY: build pgo release test
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo unknown)
# The tags every build should have; Go cannot make them the default itself.
TAGS = with_acme,with_utls,with_quic
# Optional features, e.g. make build EXTRA_TAGS=with_sentry,with_pprof
EXTRA_TAGS ?=
comma := ,
BUILD_TAGS = $(TAGS)$(if $(EXTRA_TAGS),$(comma)$(EXTRA_TAGS))
LDFLAGS = -s -w -buildid= -X github.com/The-NeXT-Project/NeXT-Server/constant.Version=$(VERSION)

# Profiles fetched by `make pgo` from a server built with with_pprof and
# configured with "pprof": {"listen": "127.0.0.1:6060"}.
PPROF_URL ?= http://127.0.0.1:6060
PPROF_SECONDS ?= 60
PGO_FILE = cmd/next-server/default.pgo

build:
	go build -v -trimpath -tags $(BUILD_TAGS) -ldflags "$(LDFLAGS)" ./cmd/next-server

# Records a CPU profile and merges it into default.pgo, which every go build
# of cmd/next-server then uses for profile-guided optimization.
pgo:
	curl -fsS -o next-server.pprof "$(PPROF_URL)/debug/pprof/profile?seconds=$(PPROF_SECONDS)"
	if [ -f $(PGO_FILE) ]; then \
		go tool pprof -proto $(PGO_FILE) next-server.pprof > merged.pprof && mv merged.pprof $(PGO_FILE); \
	else \
		mv next-server.pprof $(PGO_FILE); \
	fi
	rm -f next-server.pprof

release:
	goreleaser release --clean --skip-publish || exit 1
	mkdir -p dist/release
	mv dist/*.tar.gz dist/*.deb dist/*.rpm dist/release
	ghr --replace --draft --prerelease -p 3 "${VERSION}" dist/release
	rm -r dist

release_install:
	go install -v mvdan.cc/garble@latest
	go install -v github.com/goreleaser/goreleaser@latest
	go install -v github.com/tcnksm/ghr@latest

fmt:
	@gofumpt -l -w .
	@gofmt -s -w .
	@gci write --custom-order -s standard -s "prefix(github.com/The-NeXT-Project/)" -s "default" .

fmt_install:
	go install -v mvdan.cc/gofumpt@latest
	go install -v github.com/daixiang0/gci@latest

lint:
	GOOS=linux GOARCH=amd64 golangci-lint run ./...
	GOOS=linux GOARCH=arm64 golangci-lint run ./...

lint_install:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

test:
	go test -tags $(BUILD_TAGS) -v ./...