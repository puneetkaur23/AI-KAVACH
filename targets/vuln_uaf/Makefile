CC      = gcc
CFLAGS  = -g -O1 -Wall
ASAN    = -fsanitize=address,undefined -fno-omit-frame-pointer
AFL_CC  = afl-gcc

TARGET  = vuln_uaf

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

asan: vuln.c
	$(CC) $(CFLAGS) $(ASAN) -o $(TARGET)_asan $<

afl: vuln.c
	AFL_USE_ASAN=1 $(AFL_CC) $(CFLAGS) -o $(TARGET)_afl $<

test: asan
	@echo "=== Running unit tests ==="
	@python3 tests/test_vuln_uaf.py

clean:
	rm -f $(TARGET) $(TARGET)_asan $(TARGET)_afl

.PHONY: all asan afl test clean
