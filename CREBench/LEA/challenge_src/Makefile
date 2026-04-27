CC = gcc
CFLAGS := -O3 -Wall -Wextra -std=c11
CPPFLAGS := -I../src
LTO ?= -flto
STRIP_CMD ?= strip

SRC_DIR = ../src
PUBLIC_DIR = ../public
TARGET = $(PUBLIC_DIR)/challenge

OBJS = $(SRC_DIR)/lea-constant.o $(SRC_DIR)/lea-key.o $(SRC_DIR)/lea-utility.o $(SRC_DIR)/lea.o challenge.o key_source.o

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(PUBLIC_DIR)
	$(CC) $(CFLAGS) $(LTO) -o $@ $^
	$(STRIP_CMD) $@

$(SRC_DIR)/lea-constant.o: $(SRC_DIR)/lea-constant.c $(SRC_DIR)/lea.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(SRC_DIR)/lea-key.o: $(SRC_DIR)/lea-key.c $(SRC_DIR)/lea.h $(SRC_DIR)/lea-utility.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(SRC_DIR)/lea-utility.o: $(SRC_DIR)/lea-utility.c $(SRC_DIR)/lea-utility.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(SRC_DIR)/lea.o: $(SRC_DIR)/lea.c $(SRC_DIR)/lea.h $(SRC_DIR)/lea-utility.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

challenge.o: challenge.c $(SRC_DIR)/lea.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

key_source.o: key_source.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
