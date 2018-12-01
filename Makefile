#CC = ${CC} # C compiler
DEBUG = n
CFLAGS = -fPIC -Wall -Wextra -O2 -g # C flags
CFLAGS += -std=gnu99 -Wno-declaration-after-statement -fgnu89-inline
ifeq ($(DEBUG), y)
	CFLAGS += -D__DEBUG__
else
endif
RM = rm -f  # rm command
LIB_NAME = ccp
TARGET_LIB = lib${LIB_NAME}.so # target lib
STATIC_TARGET = lib${LIB_NAME}.a

TEST_TARGET = libccp-test
SRCS = ccp.c machine.c serialize.c ccp_priv.c # source files
OBJS = $(SRCS:.c=.o)

TEST_SRCS = test.c
TEST_OBJS = $(TEST_SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB} ${STATIC_TARGET} test

$(TARGET_LIB): $(OBJS)
	$(CC) -shared ${LDFLAGS} -o $@ $^

$(STATIC_TARGET): $(OBJS)
	ar rcs $(STATIC_TARGET) $(OBJS)

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

-include $(SRCS:.c=.d)

$(TEST_TARGET): ${TARGET_LIB} ${TEST_OBJS}
	$(CC) ${CFLAGS} -D__DEBUG__ ${TEST_SRCS} ${STATIC_TARGET} -o ${TEST_TARGET}

test: $(TEST_TARGET)
	./libccp-test

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d) ${TEST_TARGET} ${TEST_TARGET} ${STATIC_TARGET}
	-${RM} -r *.dSYM
