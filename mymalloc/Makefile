NAME := $(shell basename $(PWD))
export MODULE := M5

SRCS   := $(shell find tests/ -maxdepth 1 -name "*.c")
CFLAGS := -I.

all: $(NAME) check

check:
	gcc -DFREESTANDING -I. \
	    -ffreestanding -static -nostdlib -nostartfiles -no-pie \
	    -o malloc-check *.c && \
	        rm -f malloc-check

include ../.shadow/oslabs.mk
