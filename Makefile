CFLAGS:=-std=c99 -MMD -pedantic -Wall -Wextra -O3 -DDEBUG_ENABLE=0 -Isrc

LIB_SRCS:=src/cipher.c \
          src/encrypt.c \
          src/log.c
APP_SRCS:=src/main.c
TEST_SRCS:=test/test1.c

LIB_OBJS:=$(LIB_SRCS:%.c=%.o)
LIB_DEPS:=$(LIB_SRCS:%.c=%.d)

TEST_OBJS:=$(TEST_SRCS:%.c=%.o)
TEST_DEPS:=$(TEST_SRCS:%.c=%.d)

APP_OBJS:=$(APP_SRCS:%.c=%.o)
APP_DEPS:=$(APP_SRCS:%.c=%.d)

TEST_BIN:=tests
APP_BIN:=aes

ALL_OBJS:=${LIB_OBJS} ${TEST_OBJS} ${APP_OBJS}
ALL_DEPS:=${LIB_DEPS} ${TEST_DEPS} ${APP_DEPS}
ALL_BINS:=${TEST_BIN} ${APP_BIN}

all: ${APP_BIN}

${TEST_BIN}: ${LIB_OBJS} ${TEST_OBJS}
	${CC} ${DEFINES} $^ -o $@

${APP_BIN}: ${LIB_OBJS} ${APP_OBJS}
	${CC} ${CFLAGS} ${DEFINES} $^ -o $@

check: ${TEST_BIN}
	./${TEST_BIN}

clean:
	rm -f ${ALL_OBJS} ${ALL_DEPS} ${ALL_BINS}

.PHONY: all check clean

-include ${LIB_DEPS}
