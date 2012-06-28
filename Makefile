#!/bin/sh



ifeq ($(CC),)
  CC=gcc
endif

ifeq ($(RM),)
  RM=rm -f
endif

ifeq ($(CP),)
  CP=cp
endif


CFLAGS:=$(CFLAGS) -O3 -I/usr/include -I/usr/local/include -L/usr/lib -L/usr/local/lib
LIBS:=-lm -lpthread -lssl -lcrypto
WARNING_FLAGS:=$(WARNING_FLAGS) -Wall
DEBUG_FLAGS:=$(DEBUG_FLAGS) -g


OBJS:=src/math.o src/error.o src/linux.o src/print.o src/thread.o src/shallot.o
OBJS_DBG:=src/math.dbg.o src/error.dbg.o src/linux.dbg.o src/print.dbg.o src/thread.dbg.o src/shallot.dbg.o


all: $(OBJS)
	$(CC) $(CFLAGS) -pthread $^ -o shallot $(LIBS)

debug: $(OBJS_DBG)
	$(CC)  $(DEBUG_FLAGS) $(CFLAGS) -pthread $^ -o shallot $(LIBS)

clean:
	$(RM)  shallot src/*.o
install:
	$(CP) shallot /usr/bin/
uninstall:
	$(RM) /usr/bin/shallot



src/%.o: src/%.c
	$(CC) $(CFLAGS) $(WARNING_FLAGS) -o $@ -c $^

src/%.dbg.o: src/%.c
	$(CC) $(DEBUG_FLAGS) $(CFLAGS) $(WARNING_FLAGS) -o $@ -c $^

