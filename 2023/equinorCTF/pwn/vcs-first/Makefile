CC=gcc
CFLAGS=-Wall -Wextra  -Werror -std=c99  -no-pie
LDFLAGS = 
TARGET=vcs_first

all: $(TARGET)

$(TARGET): vcs_first.o
		$(CC) $(CFLAGS) -o $(TARGET) vcs_first.o $(LDFLAGS)

vcs_first.o: vcs_first.c
		$(CC) $(CFLAGS) -c vcs_first.c

clean:
		rm -f *.o $(TARGET)