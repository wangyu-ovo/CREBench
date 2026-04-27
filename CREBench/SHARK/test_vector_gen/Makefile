CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS =

SRC_DIR = ../src
TARGET = test_v_gen
OUTPUT ?= ../test_vectors.json

OBJS = $(SRC_DIR)/shark-constant.o $(SRC_DIR)/shark-core.o $(SRC_DIR)/shark-key.o $(SRC_DIR)/shark-math.o $(SRC_DIR)/shark.o test_v_gen.o ../challenge_src/key_source.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(SRC_DIR)/shark-constant.o: $(SRC_DIR)/shark-constant.c $(SRC_DIR)/shark.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(SRC_DIR)/shark-core.o: $(SRC_DIR)/shark-core.c $(SRC_DIR)/shark.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(SRC_DIR)/shark-key.o: $(SRC_DIR)/shark-key.c $(SRC_DIR)/shark.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(SRC_DIR)/shark-math.o: $(SRC_DIR)/shark-math.c $(SRC_DIR)/shark.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(SRC_DIR)/shark.o: $(SRC_DIR)/shark.c $(SRC_DIR)/shark.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

../challenge_src/key_source.o: ../challenge_src/key_source.c
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

test_v_gen.o: test_v_gen.c $(SRC_DIR)/shark.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

generate-vectors: $(TARGET)
	./$(TARGET) $(OUTPUT)

clean:
	rm -f $(TARGET) $(OBJS) test_v_gen.o

.PHONY: all clean generate-vectors
