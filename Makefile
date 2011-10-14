CC = gcc
CFLAGS = -Wall -g
OFLAG = -o
LIBS = `pkg-config --libs libusb-1.0`

.SUFFIXES : .o .c
.c.o :
	$(CC) $(CFLAGS) -c $<

all: zsitool

zsitool: zsitool.o
	$(CC) $(LIBS) $(OFLAG) zsitool zsitool.o

zsitool.o: zsitool.c

clean:
	rm *.o


