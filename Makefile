MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash -o pipefail
CONTAINER_ENGINE ?= docker
CONTAINER_REPO ?= "a3s"
CONTAINER_IMAGE ?= "a3s"
CONTAINER_TAG ?= "dev"

GIT_SHA=$(shell git rev-parse --short HEAD)
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
GIT_TAG=$(shell git describe --tags --abbrev=0 --match='v[0-9]*.[0-9]*.[0-9]*' 2> /dev/null | sed 's/^.//')
BUILD_DATE=$(shell date)
VERSION_PKG="go.acuvity.ai/a3s/pkgs/version"
LDFLAGS ?= -ldflags="-w -s -X '$(VERSION_PKG).GitSha=$(GIT_SHA)' -X '$(VERSION_PKG).GitBranch=$(GIT_BRANCH)' -X '$(VERSION_PKG).GitTag=$(GIT_TAG)' -X '$(VERSION_PKG).BuildDate=$(BUILD_DATE)'"

export GO111MODULE = on

default: lint vuln test a3s cli
.PHONY: ui docker

## Tests

lint:
	golangci-lint run \
		--timeout=5m \
		--disable-all \
		--exclude-use-default=false \
		--exclude=dot-imports \
		--exclude=package-comments \
		--exclude=unused-parameter \
		--exclude=dot-imports \
		--enable=errcheck \
		--enable=goimports \
		--enable=ineffassign \
		--enable=revive \
		--enable=unused \
		--enable=staticcheck \
		--enable=unconvert \
		--enable=misspell \
		--enable=prealloc \
		--enable=nakedret \
		--enable=typecheck \
		--enable=unparam \
		--enable=gosimple \
		--enable=nilerr \
		./...


test:
	go test -vet off ./... -race -cover -covermode=atomic -coverprofile=unit_coverage.out

sec:
	gosec -quiet ./...

vuln:
	govulncheck ./...


## Code generation

generate:
	go generate ./...

api:
	cd pkgs/api && make codegen

ui:
	cd internal/ui/js/login && yarn && yarn build

codegen: api ui generate


## Main build

a3s:
	cd cmd/a3s && go build $(LDFLAGS) -trimpath

a3s_linux:
	cd cmd/a3s && GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -trimpath

cli:
	cd cmd/a3sctl && CGO_ENABLED=0 go build $(LDFLAGS) -trimpath

cli_linux:
	cd cmd/a3sctl && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -trimpath

install_a3s:
	cd cmd/a3s && go install $(LDFLAGS) -trimpath

install_a3s_linux:
	cd cmd/a3s && GOOS=linux GOARCH=amd64 go install $(LDFLAGS) -trimpath

install_cli:
	cd cmd/a3sctl && CGO_ENABLED=0 go install $(LDFLAGS) -trimpath

install_cli_linux:
	cd cmd/a3sctl && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go install $(LDFLAGS) -trimpath

## Containers

docker:
	CONTAINER_ENGINE=docker make container

podman:
	CONTAINER_ENGINE=podman make container

container: codegen generate a3s_linux package_ca_certs
	mkdir -p docker/in
	cp cmd/a3s/a3s docker/in
	cd docker && ${CONTAINER_ENGINE} build -t ${CONTAINER_REPO}/${CONTAINER_IMAGE}:${CONTAINER_TAG} .

package_ca_certs:
	mkdir -p docker/in
	go install github.com/agl/extract-nss-root-certs@latest
	curl -s https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt -o certdata.txt
	mkdir -p docker/in
	extract-nss-root-certs > docker/in/ca-certificates.pem
	rm -f certdata.txt
