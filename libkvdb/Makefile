NAME := $(shell basename $(PWD))
export MODULE := M9

CFLAGS += -I.
LIB_SRCS := $(shell find . -maxdepth 1 -name "*.c")
TEST_SRCS := $(shell find tests/ -maxdepth 1 -name "*.c") ../testkit/testkit.c

all: $(NAME).so $(NAME)_test

$(NAME).so: $(LIB_SRCS) $(shell find . -name "*.h")
	gcc $(CFLAGS) -fPIC -shared -o $(NAME).so $(LIB_SRCS)

$(NAME)_test: $(TEST_SRCS) $(NAME).so $(shell find . -name "*.h")
	gcc $(CFLAGS) -o $(NAME)_test $(TEST_SRCS) $(NAME).so

include ../.shadow/oslabs.mk
