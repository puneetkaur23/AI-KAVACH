CC      = gcc
CFLAGS  = -g -O1 -Wall
ASAN    = -fsanitize=address,undefined -fno-omit-frame-pointer
AFL_CC  = afl-gcc

TARGET  = clean_target

all: $(TARGET)

$(TARGET): clean.c
	$(CC) $(CFLAGS) -o $@ $<

asan: clean.c
	$(CC) $(CFLAGS) $(ASAN) -o $(TARGET)_asan $<

afl: clean.c
	AFL_USE_ASAN=1 $(AFL_CC) $(CFLAGS) -o $(TARGET)_afl $<

clean:
	rm -f $(TARGET) $(TARGET)_asan $(TARGET)_afl

.PHONY: all asan afl clean
