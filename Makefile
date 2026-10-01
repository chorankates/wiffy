.PHONY: build run clean deps install sudoers uninstall-sudoers

build:
	go build -o wiffy .

run: build
	./wiffy

clean:
	rm -f wiffy wiffy.db wiffy.db-journal wiffy.db-wal wiffy.db-shm

deps:
	go mod download
	go mod tidy

install:
	go install .

dev:
	go run main.go


# Passwordless sudo for nmap (quick, MAC and deep scans run it as root). Validated with visudo before install.
SUDOERS_FILE := /etc/sudoers.d/wiffy
NMAP_PATH := $(shell command -v nmap)
SUDO_USER_NAME := $(shell id -un)

sudoers:
	@test -n "$(NMAP_PATH)" || { echo "nmap not found in PATH"; exit 1; }
	@tmp=$$(mktemp) && \
	echo "$(SUDO_USER_NAME) ALL=(root) NOPASSWD: $(NMAP_PATH)" > $$tmp && \
	sudo visudo -cf $$tmp && \
	sudo install -m 0440 -o root -g $$(id -gn root) $$tmp $(SUDOERS_FILE); \
	status=$$?; rm -f $$tmp; exit $$status
	@echo "installed $(SUDOERS_FILE): $(SUDO_USER_NAME) may run $(NMAP_PATH) as root without a password"

uninstall-sudoers:
	sudo rm -f $(SUDOERS_FILE)
