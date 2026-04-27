CC := cc
CFLAGS := -O3 -Wall -Wextra -std=c11
CPPFLAGS := -I../src
LDFLAGS :=
STRIP_CMD ?= strip

SRCS := challenge.c key_source.c ../src/rc4.c
OBJS := $(SRCS:.c=.o)

PUBLIC_DIR := ../public
TARGET ?= $(PUBLIC_DIR)/challenge

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(dir $(TARGET))
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
	$(STRIP_CMD) $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
