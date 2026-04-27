CC = cc
CFLAGS = -O3 -Wall -Wextra -std=c11
LTO ?= -flto
STRIP_CMD ?= strip
INC = -I../src

TARGET = ../public/challenge
SRCS = challenge.c key_source.c ../src/misty1.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter-out ../src/misty1.o,$(OBJS)) ../src/misty1.o

%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
	rm -f ../src/misty1.o
