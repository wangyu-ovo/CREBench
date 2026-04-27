CC = gcc
CFLAGS := -O3 -Wall -Wextra -std=c11
CPPFLAGS := -I../src
LTO ?= -flto
STRIP_CMD ?= strip

SRC_DIR = ../src
PUBLIC_DIR = ../public
TARGET = $(PUBLIC_DIR)/challenge

OBJS = $(SRC_DIR)/sc2000.o challenge.o key_source.o

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(PUBLIC_DIR)
	$(CC) $(CFLAGS) $(LTO) -o $@ $^
	$(STRIP_CMD) $@

$(SRC_DIR)/sc2000.o: $(SRC_DIR)/sc2000.c $(SRC_DIR)/sc2000.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

challenge.o: challenge.c $(SRC_DIR)/sc2000.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

key_source.o: key_source.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
