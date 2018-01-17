CC = gcc # C compiler
CFLAGS = -fPIC -Wall -Wextra -O2 -g # C flags
CFLAGS += -D__USRLIB__ # Only use this makefile for compiling user-space library
LDFLAGS = -shared  # linking flags
RM = rm -f  # rm command
LIB_NAME = ccp
TARGET_LIB = lib${LIB_NAME}.so # target lib

TEST_TARGET = libccp-test
SRCS = ccp.c send_machine.c measurement_machine.c serialize.c ccp_priv.c # source files
OBJS = $(SRCS:.c=.o)

TEST_SRCS = test.c

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

$(TEST_TARGET): ${TARGET_LIB}
	$(CC) ${CFLAGS} ${TEST_SRCS} -L . -l ${LIB_NAME} -o ${TEST_TARGET}

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d) ${TEST_TARGET} ${TEST_TARGET}
	-${RM} -r *.dSYM

