CC ?= gcc
CFLAGS = -Wall -g `pkg-config --cflags libusb-1.0`
OFLAG = -o
LIBS = `pkg-config --libs libusb-1.0`

.SUFFIXES : .o .c
.c.o :
	$(CC) $(CFLAGS) -c $<

all: zsitool

zsitool: zsitool.o
	$(CC) $(OFLAG) zsitool zsitool.o $(LIBS)

zsitool.o: zsitool.c

clean:
	rm *.o


