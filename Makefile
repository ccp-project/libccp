CC = gcc # C compiler
CFLAGS = -fPIC -Wall -Wextra -O2 -g # C flags
CFLAGS += -D__USRLIB__ # Only use this makefile for compiling user-space library
LDFLAGS = -shared  # linking flags
RM = rm -f  # rm command
TARGET_LIB = libccp.so # target lib

SRCS = ccp.c send_machine.c measurement_machine.c serialize.c ccp_priv.c# source files
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d)

