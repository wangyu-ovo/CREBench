CC = cc
CFLAGS = -O3 -Wall -Wextra -std=c11

.PHONY: all clean demo challenge public

all: demo challenge

demo:
	$(MAKE) -C demo

challenge:
	$(MAKE) -C challenge_src

public: challenge
	mkdir -p public
	cp challenge_src/challenge public/

clean:
	$(MAKE) -C demo clean
	$(MAKE) -C challenge_src clean
	rm -rf public/challenge

