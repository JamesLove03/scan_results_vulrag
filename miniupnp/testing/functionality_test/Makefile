CC ?= gcc
CFLAGS_COMMON = -Wall -Wextra -g

all: test_overflow test_overflow_protected

# Without stack protector: shows silent memory corruption
test_overflow: test_udplite_overflow.c
	$(CC) $(CFLAGS_COMMON) -fno-stack-protector -o $@ $<

# With stack protector: shows crash/abort on canary detection
test_overflow_protected: test_udplite_overflow.c
	$(CC) $(CFLAGS_COMMON) -fstack-protector-all -o $@ $<

run: all
	@echo "========== Without stack protector =========="
	./test_overflow
	@echo ""
	@echo "========== With stack protector =========="
	./test_overflow_protected; true

clean:
	rm -f test_overflow test_overflow_protected

.PHONY: all run clean
