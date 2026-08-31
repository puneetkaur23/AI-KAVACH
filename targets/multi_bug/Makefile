CC      = gcc
CFLAGS  = -g -O1 -Wall
ASAN    = -fsanitize=address,undefined -fno-omit-frame-pointer
AFL_CC  = afl-gcc

TARGET  = multi_bug

all: $(TARGET)

$(TARGET): multi.c
	$(CC) $(CFLAGS) -o $@ $<

asan: multi.c
	$(CC) $(CFLAGS) $(ASAN) -o $(TARGET)_asan $<

afl: multi.c
	AFL_USE_ASAN=1 $(AFL_CC) $(CFLAGS) -o $(TARGET)_afl $<

clean:
	rm -f $(TARGET) $(TARGET)_asan $(TARGET)_afl

.PHONY: all asan afl clean
