override SHELL := /bin/sh

VERSION ?= 0.2.0
BUILD_DIR ?= bin
DIST_DIR ?= dist
GITCTX_GITHUB_CLIENT_ID ?=

# Freeze command-line values without asking make to expand any make functions
# they might contain. The shell receives the exact text and the scripts perform
# their own validation.
override VERSION := $(value VERSION)
override BUILD_DIR := $(value BUILD_DIR)
override DIST_DIR := $(value DIST_DIR)
override GITCTX_GITHUB_CLIENT_ID := $(value GITCTX_GITHUB_CLIENT_ID)

# Export user-supplied values and expand them only as quoted shell variables.
# Expanding them textually inside a recipe would allow shell syntax in a Make
# command-line variable to be interpreted before the scripts can validate it.
export VERSION BUILD_DIR DIST_DIR GITCTX_GITHUB_CLIENT_ID

.PHONY: all build test race vet check install uninstall release release-test

all: build

build:
	@case "$$VERSION" in ''|*[!A-Za-z0-9._+-]*|*[.][.]*|[!0-9]*) printf '%s\n' "make build: invalid VERSION" >&2; exit 1 ;; esac
	@case "$$GITCTX_GITHUB_CLIENT_ID" in *[!A-Za-z0-9._-]*) printf '%s\n' "make build: invalid public GitHub Client ID" >&2; exit 1 ;; esac; if [ -n "$$GITCTX_GITHUB_CLIENT_ID" ]; then [ "$${#GITCTX_GITHUB_CLIENT_ID}" -ge 8 ] && [ "$${#GITCTX_GITHUB_CLIENT_ID}" -le 128 ] || exit 1; fi
	@mkdir -p "$$BUILD_DIR"
	TMPDIR= GOTMPDIR= CGO_ENABLED=0 GOOS= GOARCH= GOAMD64= GOARM64= GOEXPERIMENT= GOFIPS140=off GO111MODULE=on GOENV=off GOFLAGS= GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go build -mod=readonly -buildvcs=false -trimpath -ldflags "-s -w -X main.version=$$VERSION -X gitctx/internal/githubkeys.OAuthClientID=$$GITCTX_GITHUB_CLIENT_ID" -o "$$BUILD_DIR/gitctx" ./cmd/gitctx

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

check: test race vet

install:
	./scripts/install.sh --version "$$VERSION"

uninstall:
	./scripts/uninstall.sh

release:
	./scripts/release.sh --version "$$VERSION" --output-dir "$$DIST_DIR"

release-test:
	./scripts/test-release.sh
