CC      = gcc
CFLAGS  = -g -O1 -Wall
ASAN    = -fsanitize=address,undefined -fno-omit-frame-pointer
AFL_CC  = afl-gcc

TARGET  = custom_sample_vulnerable_target

all: $(TARGET)

$(TARGET): sample_vulnerable_target.c
	$(CC) $(CFLAGS) -o $@ $<

asan: sample_vulnerable_target.c
	$(CC) $(CFLAGS) $(ASAN) -o $(TARGET)_asan $<

afl: sample_vulnerable_target.c
	$(AFL_CC) $(CFLAGS) $(ASAN) -o $(TARGET)_afl $<

clean:
	rm -f $(TARGET) $(TARGET)_asan $(TARGET)_afl

.PHONY: all asan afl clean
