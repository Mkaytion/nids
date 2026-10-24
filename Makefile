# nids -- offline Network Intrusion Detection System (Phase 2: signature matching)
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
#   make test     run samples/test.pcap against samples/test.rules
#   make bench    synthetic benchmark -> bench/RESULTS.md
#   make bench-real    real-traffic benchmark -> bench/CIC-IDS2018.md
#   make clean    remove build artifacts

CC      = gcc
# gnu11 (not c11): libpcap's headers use BSD types (u_char, u_int, ...) that
# glibc hides in strict-ISO mode. gnu11 = C11 + GNU/BSD defaults, so they exist.
CFLAGS  = -std=gnu11 -Wall -Wextra -Wpedantic -O2 -Iinclude
LDLIBS  = -lpcap                 # link libpcap (note: after objects on the link line)

SRC     = src/ids.c src/sigmatch.c
OBJ     = $(SRC:src/%.c=build/%.o)
BIN     = build/ids

.PHONY: all run test bench bench-real clean

all: $(BIN)

$(BIN): $(OBJ) | build
	$(CC) -o $@ $(OBJ) $(LDLIBS)

build/%.o: src/%.c $(wildcard include/*.h) | build
	$(CC) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build

# Usage: make run PCAP=samples/attack.pcap
run: $(BIN)
	./$(BIN) $(PCAP)

# Golden test: exercises overlapping, duplicate, hex and repeated matches.
test: $(BIN)
	./$(BIN) samples/test.pcap samples/test.rules | grep '^ALERT' > build/test.out
	diff -u samples/test.expected build/test.out && echo "test: PASS"

# Benchmarks (see bench/): a synthetic suite, and real traffic from
# CSE-CIC-IDS2018 (bench-real downloads ~1.8 GB into $(DATA)).
bench: $(BIN) | build
	$(CC) $(CFLAGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -o build/ids_asan $(SRC) $(LDLIBS)
	python3 bench/bench.py $(BIN) build/ids_asan build/bench

DATA ?= build/cicids2018
bench-real: $(BIN)
	python3 bench/cicids2018.py fetch $(DATA)
	python3 bench/cicids2018.py eval $(BIN) rules/default.rules $(DATA)

clean:
	rm -rf build
