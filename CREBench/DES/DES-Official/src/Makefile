# DES Implementation Makefile
# ========================

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99

# Source files
DES_SOURCES = des.c

# Object files
DES_OBJECTS = $(DES_SOURCES:.c=.o)

# Default target
all: $(DES_OBJECTS)

# Compile DES implementation
DES_OBJECTS: des.c des.h
	$(CC) $(CFLAGS) -c des.c -o des.o

# Clean build artifacts
clean:
	rm -f $(DES_OBJECTS)

# Clean and rebuild
rebuild: clean all

# Show help
help:
	@echo "DES Implementation Build System"
	@echo "=============================="
	@echo "Available targets:"
	@echo "  all      - Build the DES object file (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  rebuild  - Clean and rebuild everything"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Files:"
	@echo "  des.h      - DES header file"
	@echo "  des.c      - DES implementation"

.PHONY: all clean rebuild help
