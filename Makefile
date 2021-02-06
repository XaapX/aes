CFLAGS:=-std=c99 -MMD -pedantic -Wall -Wextra -O3 -DDEBUG_ENABLE=0
LIB_SRCS:=aes.c enc.c log.c
TEST_SRCS:=test.c

LIB_OBJS:=$(LIB_SRCS:%.c=%.o)
LIB_DEPS:=$(LIB_SRCS:%.c=%.d)

TEST_OBJS:=$(TEST_SRCS:%.c=%.o)
TEST_DEPS:=$(TEST_SRCS:%.c=%.d)

ALL_OBJS:=${LIB_OBJS} ${TEST_OBJS}
ALL_DEPS:=${LIB_DEPS} ${TEST_DEPS}

TEST_BIN:=test

all: ${TEST_BIN}

${TEST_BIN}: ${LIB_OBJS} ${TEST_OBJS}
	${CC} ${DEFINES} $^ -o $@

check: ${TEST_BIN} Makefile
	./${TEST_BIN}

clean:
	rm -f ${ALL_OBJS} ${ALL_DEPS} ${TEST_BIN}

.PHONY: all check clean

-include ${LIB_DEPS}
