export TOKEN := ???

# ---------- DO NOT MODIFY ----------

export COURSE := OS2025
URL := 'https://jyywiki.cn/submit.sh'

ifeq ($(NAME),)
$(error Should make in each lab's directory)
endif

SRCS   += $(shell find . -maxdepth 1 -name "*.c")
DEPS   += $(shell find . -maxdepth 1 -name "*.h") $(SRCS) ../testkit/testkit.h ../testkit/testkit.c
CFLAGS  += -O2 -std=gnu2x -ggdb -Wall -I../testkit
LDFLAGS += 


.PHONY: all git-trace test clean submit commit-and-make

.DEFAULT_GOAL := commit-and-make
commit-and-make: git-trace all

$(NAME): $(DEPS)
	$(CC) $(CFLAGS) $(SRCS) ../testkit/testkit.c -o $@ $(LDFLAGS)

lib$(NAME).so: $(DEPS)
	$(CC) -fPIC -shared $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)

clean:
	rm -f lib$(NAME).so $(NAME) $(NAME).so $(NAME)_test

git-trace:
	@find ../.shadow/ -maxdepth 1 -type d -name '[a-z]*' | xargs rm -rf
	@cp -r `find .. -maxdepth 1 -type d -name '[a-z]*'` ../.shadow/
	@git add ../.shadow -A --ignore-errors
	@while (test -e .git/index.lock); do sleep 0.1; done
	@(uname -a; uptime) | git commit -F - -q --author='tracer-nju <tracer@nju.edu.cn>' --no-verify --allow-empty
	@sync

submit:
	@cd $(dir $(abspath $(lastword $(MAKEFILE_LIST)))) && \
	  curl -sSLf '$(URL)' > /dev/null && \
	  curl -sSLf '$(URL)' | bash
