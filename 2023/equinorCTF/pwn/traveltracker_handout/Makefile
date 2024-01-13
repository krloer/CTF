CC=gcc
CFLAGS=-Wall -Wextra  -std=c99 -m32
LDFLAGS = 
TARGET=travel_tracker

all: $(TARGET)

$(TARGET): travel_tracker.o
		$(CC) $(CFLAGS) -o $(TARGET) travel_tracker.o $(LDFLAGS)

travel_tracker.o: travel_tracker.c
		$(CC) $(CFLAGS) -c travel_tracker.c

clean:
		rm -f *.o $(TARGET)