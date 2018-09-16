AR=ar
CC=gcc
CFLAGS=-O0 -g -fpic -pedantic -Wall

all: libaes.so libaes.a

libaes.a: aes.o
	$(AR) rcs $@ $<

libaes.so: aes.o
	$(CC) -shared -o $@ $< 

aes.o: aes.c aes.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf libaes.so libaes.a *.o
