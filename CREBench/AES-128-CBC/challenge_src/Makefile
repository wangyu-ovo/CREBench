CC := cc
CFLAGS := -O3 -Wall -Wextra -std=c11
CPPFLAGS := -I../src
LDFLAGS :=
LTO ?= -flto
STRIP_CMD ?= strip

SRCS := challenge.c key_source.c ../src/aes.c
OBJS := $(SRCS:.c=.o)

TARGET := ../public/challenge

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p ../public
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LTO)
	$(STRIP_CMD) $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
