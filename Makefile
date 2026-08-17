PREFIX ?= /usr/local
DESTDIR ?=
VERSION ?= dev
SYSTEMD_UNIT_DIR ?= /usr/lib/systemd/system

.PHONY: all build test check check-bpf stress release-candidate install uninstall

all: build

build:
	go build -trimpath -ldflags '-X main.version=$(VERSION)' -o tunless ./cmd/tunless

test:
	go test -race ./...

check: test
	go vet ./...
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/tunless-linux-amd64 ./cmd/tunless
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/tunless-windows-amd64.exe ./cmd/tunless
	cd macos && swift test

check-bpf:
	./scripts/verify-bpf.sh

stress:
	./scripts/stress.sh

release-candidate:
	./scripts/release-check.sh '$(VERSION)'

install: build
	install -d '$(DESTDIR)$(PREFIX)/bin'
	install -m 0755 tunless '$(DESTDIR)$(PREFIX)/bin/tunless'
	install -d '$(DESTDIR)$(SYSTEMD_UNIT_DIR)'
	install -m 0644 packaging/systemd/tunless.service '$(DESTDIR)$(SYSTEMD_UNIT_DIR)/tunless.service'

uninstall:
	rm -f '$(DESTDIR)$(PREFIX)/bin/tunless' '$(DESTDIR)$(SYSTEMD_UNIT_DIR)/tunless.service'
