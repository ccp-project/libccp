CC = gcc # C compiler
CFLAGS = -fPIC -Wall -Wextra -O2 -g # C flags
CFLAGS += -D__USRLIB__ # Only use this makefile for compiling user-space library
ifeq ($(DEBUG), 1)
	CFLAGS += -D__DEBUG__
else
endif
LDFLAGS = -shared  # linking flags
RM = rm -f  # rm command
LIB_NAME = ccp
TARGET_LIB = lib${LIB_NAME}.so # target lib

TEST_TARGET = libccp-test
INTEGRATE_TARGET = integration-test
SRCS = ccp.c machine.c serialize.c ccp_priv.c # source files
OBJS = $(SRCS:.c=.o)

TEST_SRCS = test.c
TEST_OBJS = $(TEST_SRCS:.c=.o)

INTEGRATE_SRCS= integration_test.c
INTEGRATE_OBS = $(INTEGRATE_SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB} test

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

$(TEST_TARGET): ${TARGET_LIB} ${TEST_OBJS}
	$(CC) ${CFLAGS} -D__DEBUG__ ${TEST_SRCS} -L. -l${LIB_NAME} -o ${TEST_TARGET}

test: $(TEST_TARGET)
	LD_LIBRARY_PATH=. ./libccp-test

$(INTEGRATE_TARGET): ${TARGET_LIB} ${INTEGRATE_OBJS}
	$(CC) ${CFLAGS} ${INTEGRATE_SRCS} -L . -l ${LIB_NAME} -o ${INTEGRATE_TARGET}

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d) ${TEST_TARGET} ${TEST_TARGET} ${INTEGRATE_TARGET}
	-${RM} -r *.dSYM
