CC = gcc
CFLAGS := -O3 -Wall -Wextra -std=c11
CPPFLAGS := -I../src
LTO ?= -flto
STRIP_CMD ?= strip

SRC_DIR = ../src
PUBLIC_DIR = ../public
TARGET = $(PUBLIC_DIR)/challenge

OBJS = $(SRC_DIR)/kalyna-constant.o $(SRC_DIR)/kalyna-key.o $(SRC_DIR)/kalyna-utility.o $(SRC_DIR)/kalyna.o challenge.o key_source.o

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(PUBLIC_DIR)
	$(CC) $(CFLAGS) $(LTO) -o $@ $^
	$(STRIP_CMD) $@

$(SRC_DIR)/kalyna-constant.o: $(SRC_DIR)/kalyna-constant.c $(SRC_DIR)/kalyna.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(SRC_DIR)/kalyna-key.o: $(SRC_DIR)/kalyna-key.c $(SRC_DIR)/kalyna.h $(SRC_DIR)/kalyna-utility.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(SRC_DIR)/kalyna-utility.o: $(SRC_DIR)/kalyna-utility.c $(SRC_DIR)/kalyna-utility.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(SRC_DIR)/kalyna.o: $(SRC_DIR)/kalyna.c $(SRC_DIR)/kalyna.h $(SRC_DIR)/kalyna-utility.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

challenge.o: challenge.c $(SRC_DIR)/kalyna.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

key_source.o: key_source.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
