# Makefile for Camellia Challenge
# Compiles challenge program and outputs stripped executable to public directory

CC = gcc
CFLAGS := -O3 -Wall -Wextra -std=c11
LDFLAGS =
LTO ?= -flto
STRIP_CMD ?= strip

# Directories
SRC_DIR = ../src
CHALLENGE_DIR = .
PUBLIC_DIR = ../public

# Target executable
TARGET = $(PUBLIC_DIR)/challenge

# Object files
OBJS = $(SRC_DIR)/camellia.o challenge.o key_source.o

# Default target
all: $(TARGET)

# Create public directory if it doesn't exist and compile
$(TARGET): $(OBJS)
	mkdir -p $(PUBLIC_DIR)
	$(CC) $(LDFLAGS) -o $@ $^
	$(STRIP_CMD) $@

# Compile camellia.c
$(SRC_DIR)/camellia.o: $(SRC_DIR)/camellia.c $(SRC_DIR)/camellia.h
	$(CC) $(CFLAGS) -c $< -o $@

# Compile challenge.c
challenge.o: challenge.c $(SRC_DIR)/camellia.h
	$(CC) $(CFLAGS) -c $< -o $@

# Compile key_source.c
key_source.o: key_source.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(TARGET) $(OBJS)

# Clean public directory
clean-public:
	rm -f $(PUBLIC_DIR)/challenge

# Test the challenge (example usage)
test: $(TARGET)
	@echo "Testing with sample input..."
	$(TARGET) "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build the challenge (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  clean-public - Remove challenge executable from public directory"
	@echo "  test         - Build and test the challenge"
	@echo "  help         - Show this help"

.PHONY: all clean clean-public test help
