CFLAGS:=-std=c99 -MMD -pedantic -Wall -Wextra -O3 -DDEBUG_ENABLE=0
SRCS:=aes.c enc.c log.c test.c
OBJS:=$(SRCS:%.c=%.o)

all: test

test: ${OBJS}
	${CC} ${DEFINES} $^ -o $@

check: test Makefile
	./test

clean:
	rm -f *.o *.d test

.PHONY: all check clean

-include *.d