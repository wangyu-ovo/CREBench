CC := cc
CFLAGS := -O3 -Wall -Wextra -std=c11
CPPFLAGS := -I../src
LDFLAGS :=

SRCS := test_v_gen.c ../challenge_src/key_source.c ../src/rc4.c
OBJS := $(SRCS:.c=.o)

TARGET := test_v_gen
OUTPUT ?= ../test_vectors.json

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

generate-vectors: $(TARGET)
	./$(TARGET) $(OUTPUT)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean generate-vectors

