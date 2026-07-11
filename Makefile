# nids -- offline Network Intrusion Detection System (Phase 1: parser)
#
# Requires libpcap development headers:
#     Debian/Ubuntu:  sudo apt-get install libpcap-dev
#     Fedora:         sudo dnf install libpcap-devel
#
# Linux / WSL only -- libpcap is native there. (On Windows it would need
# Npcap + a different build; this project targets Linux.)
#
# Targets:
#   make          build build/ids
#   make run PCAP=file.pcap    build then run against a capture file
#   make clean    remove build artifacts

CC      = gcc
# gnu11 (not c11): libpcap's headers use BSD types (u_char, u_int, ...) that
# glibc hides in strict-ISO mode. gnu11 = C11 + GNU/BSD defaults, so they exist.
CFLAGS  = -std=gnu11 -Wall -Wextra -Wpedantic -O2 -Iinclude
LDLIBS  = -lpcap                 # link libpcap (note: after objects on the link line)

SRC     = src/ids.c
OBJ     = $(SRC:src/%.c=build/%.o)
BIN     = build/ids

.PHONY: all run clean

all: $(BIN)

$(BIN): $(OBJ) | build
	$(CC) -o $@ $(OBJ) $(LDLIBS)

build/%.o: src/%.c include/net_structs.h | build
	$(CC) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build

# Usage: make run PCAP=samples/attack.pcap
run: $(BIN)
	./$(BIN) $(PCAP)

clean:
	rm -rf build
