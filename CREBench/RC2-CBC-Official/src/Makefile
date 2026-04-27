CC := cc
CFLAGS := -O3 -Wall -Wextra -std=c11
CPPFLAGS := -I/usr/local/include
LDFLAGS := -L/usr/local/lib -lcrypto

SRCS := rc2.c demo.c
OBJS := $(SRCS:.c=.o)

TARGET := ../public/rc2_demo

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p ../public
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) -flto
	strip $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
