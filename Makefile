# Unix AR, only needed for the libaes.a target
AR=ar 

# c90-compliant C compiler
CC=gcc

# Build flags 
CFLAGS=-O0 -g -fpic -std=c90 -pedantic


libaes.a: aes.o
	$(AR) rcs $@ $<

libaes.so: aes.o
	$(CC) -shared -o $@ $< 

aes.o: aes.c aes.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf libaes.so libaes.a *.o
