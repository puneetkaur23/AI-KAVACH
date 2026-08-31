CC      = gcc
CFLAGS  = -g -O1 -Wall
ASAN    = -fsanitize=address,undefined -fno-omit-frame-pointer
AFL_CC  = afl-gcc

TARGET  = custom_api_test_upload

all: $(TARGET)

$(TARGET): test_prog.c
	$(CC) $(CFLAGS) -o $@ $<

asan: test_prog.c
	$(CC) $(CFLAGS) $(ASAN) -o $(TARGET)_asan $<

afl: test_prog.c
	$(AFL_CC) $(CFLAGS) $(ASAN) -o $(TARGET)_afl $<

clean:
	rm -f $(TARGET) $(TARGET)_asan $(TARGET)_afl

.PHONY: all asan afl clean
