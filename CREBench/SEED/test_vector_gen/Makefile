CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS =

SRC_DIR = ../src
TARGET = test_v_gen
OUTPUT ?= ../test_vectors.json

OBJS = $(SRC_DIR)/seed-constant.o $(SRC_DIR)/seed-core.o $(SRC_DIR)/seed-g.o $(SRC_DIR)/seed-key.o test_v_gen.o ../challenge_src/key_source.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(SRC_DIR)/seed-constant.o: $(SRC_DIR)/seed-constant.c $(SRC_DIR)/seed.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(SRC_DIR)/seed-core.o: $(SRC_DIR)/seed-core.c $(SRC_DIR)/seed.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(SRC_DIR)/seed-g.o: $(SRC_DIR)/seed-g.c $(SRC_DIR)/seed.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(SRC_DIR)/seed-key.o: $(SRC_DIR)/seed-key.c $(SRC_DIR)/seed.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

../challenge_src/key_source.o: ../challenge_src/key_source.c
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

test_v_gen.o: test_v_gen.c $(SRC_DIR)/seed.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

generate-vectors: $(TARGET)
	./$(TARGET) $(OUTPUT)

clean:
	rm -f $(TARGET) $(OBJS) test_v_gen.o

.PHONY: all clean generate-vectors
