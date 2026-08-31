CC      = gcc
CFLAGS  = -g -O1 -Wall
ASAN    = -fsanitize=address,undefined -fno-omit-frame-pointer
AFL_CC  = afl-gcc

TARGET  = demo_packet_parser

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

asan: vuln.c
	$(CC) $(CFLAGS) $(ASAN) -o $(TARGET)_asan $<

afl: vuln.c
	$(AFL_CC) $(CFLAGS) $(ASAN) -o $(TARGET)_afl $<

test: asan
	@echo "=== Running unit tests ==="
	@python3 tests/test_parser.py

clean:
	rm -f $(TARGET) $(TARGET)_asan $(TARGET)_afl

.PHONY: all asan afl test clean
