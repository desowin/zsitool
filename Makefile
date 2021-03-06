CC ?= gcc
EXTRA_CFLAGS ?=
EXTRA_LDFLAGS ?=
CFLAGS := $(shell pkg-config --cflags libusb-1.0) $(shell libgcrypt-config --cflags) -Wall -g -ansi -std=c99 $(EXTRA_CFLAGS)
LDFLAGS = $(EXTRA_LDFLAGS) -Wl,--as-needed
LDADD := $(shell pkg-config --libs libusb-1.0)  $(shell libgcrypt-config --libs) -lgmp -lelf
OBJECTS = zsitool.o signature.o srr.o
DEPFILES = $(foreach m,$(OBJECTS:.o=),.$(m).m)

.PHONY : clean distclean all
%.o : %.c
	$(CC) $(CFLAGS) -c $<

.%.m : %.c
	$(CC) $(CFLAGS) -M -MF $@ -MG $<

all: zsitool

zsitool: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $+ $(LDADD)

clean:
	rm -f *.o *.*.m

distclean : clean
	rm -f .*.m
	rm -f zsitool

NODEP_TARGETS := clean distclean
depinc := 1
ifneq (,$(filter $(NODEP_TARGETS),$(MAKECMDGOALS)))
depinc := 0
endif
ifneq (,$(fitler-out $(NODEP_TARGETS),$(MAKECMDGOALS)))
depinc := 1
endif

ifeq ($(depinc),1)
-include $(DEPFILES)
endif
