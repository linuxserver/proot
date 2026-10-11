CC      ?= gcc
CFLAGS  ?= -O2 -Wall
all: sysbench stopcost
sysbench: sysbench.c
	$(CC) $(CFLAGS) -pthread -o $@ $<
stopcost: stopcost.c
	$(CC) $(CFLAGS) -pthread -o $@ $<
clean:
	rm -f sysbench stopcost
.PHONY: all clean
