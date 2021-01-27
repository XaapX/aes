DEFINES=-DDEBUG_ENABLE=1

all: aes.o

aes.o: aes.c aes.h Makefile common.h
	${CC} -std=c99 ${DEFINES} -pedantic -Wall -Wextra -O3 -c aes.c -o aes.o

log.o: log.c log.h Makefile common.h
	${CC} -std=c99 ${DEFINES} -pedantic -Wall -Wextra -O3 -c log.c -o log.o

test.o: test.c Makefile common.h
	${CC} -std=c99 ${DEFINES} -pedantic -Wall -Wextra -O3 -c test.c -o test.o

test: aes.o test.o Makefile log.o
	${CC} -std=c99 ${DEFINES} -pedantic -Wall -Wextra -O3 aes.o test.o log.o -o test

check: test Makefile
	./test

clean:
	rm -f *.o test

.PHONY: all check clean