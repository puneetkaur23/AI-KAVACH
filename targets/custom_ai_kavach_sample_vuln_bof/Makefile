CC      = gcc
CFLAGS  = -g -O1 -Wall
ASAN    = -fsanitize=address,undefined -fno-omit-frame-pointer
AFL_CC  = afl-gcc

TARGET  = custom_ai_kavach_sample_vuln_bof

all: $(TARGET)

$(TARGET): ai_kavach_sample_vuln_bof.c
	$(CC) $(CFLAGS) -o $@ $<

asan: ai_kavach_sample_vuln_bof.c
	$(CC) $(CFLAGS) $(ASAN) -o $(TARGET)_asan $<

afl: ai_kavach_sample_vuln_bof.c
	$(AFL_CC) $(CFLAGS) $(ASAN) -o $(TARGET)_afl $<

clean:
	rm -f $(TARGET) $(TARGET)_asan $(TARGET)_afl

.PHONY: all asan afl clean
