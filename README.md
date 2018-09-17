aes.c
===

A simple implementation of the AES algorythm, made as part of a
self-imposed challange I took after a friend of mine mentioned he'd
have to fully implement it by the end of 2018. In the end, this
project ended up taking me, roughly, two afternoons (an hour and a
half in the first session, and then a whole day in the other) to go
from completely clueless as to what AES even was, exactly, to having
a functioning implementation.

# Features
Generally, encryption to and decryption from AES streams.

Before we can get into any specifics, however, some aspects of the
functioning of AES, or, more broadly, the Rijndael Cipher, must be
taken note of:
* KBR triplets: Consist in triplets of key length, block size
and round count. For Rijndael is a cyclic cipher working on
discrete constant-sized blocks of data, this is the single
value that will actually determine how the algorythm will run.
For AES, specifically, this value will determine which
variation of the algortythm, such as AES-128 or AES-256, will
be executed (See the 
["AES KBR table"](https://github.com/DarkRyu550/aes.c#aes-kbr-table)
section for which values
correspond to which variations).
* S-Boxes: 16x16 1-byte valued matrices used in determined
steps of the cipher algorythm for replacing byte values one to
one in a determined fashion. In Rijndael, there are default
values for these S-Boxes. For more information on their
functionality, one may reffer to
[this Wikipedia article](https://en.wikipedia.org/wiki/S-box).

Specifics:
* Encryption in any KBR triplet.
* Decryption in any KBR triplet.
* Custom KBR triplets: This implementation should, in theory,
be able to handle any KBR triplet. However, even though it
will comply in running any given variation of the algorythm,
only very specific triplets, namely, the ones listed under
["AES KBR table"](https://github.com/DarkRyu550/aes.c#aes-kbr-table)
have any guarantee of proper functionality.
Note that "guarantee" here is used loosely, as I provide no
real guarantee aside from the fact they have worked in my
personal unit tests, so your mileage may vary.
* Custom S-Boxes: Apart from custom KBR tables, this
implementation also supports the use of custom S-Boxes, so
long as you provide both the S-Box and its inverse, keep in
mind that you are to be sure the inverse is valid, as the
implementation does nothing to ensure that.

# AES KBR table
This is a list of the KBR triplets used in AES:
* `{4, 4, 10}`: For AES-128.
* `{6, 4, 12}`: For AES-196.
* `{8, 4, 14}`: For AES-256.

# Compiling
In order to compile this project, the only requirements are:
* Access to a relatively modern C compiler (although this
should be compileable even by `c90` compilers).
* Functional implementations for both `malloc()` and
`free()` (which means this library can run on freestanding
environments).
* Optionally, access to a POSIX-compliant version of `make`,
although the library should be simple enough to compile
yourself or to integrate into whatever build system one is
already using.

If one chooses to run `make`, however, before doing so  it is
advisable for them to edit the `Makefile` provided with the project.
Its fields should be obvious enough to need no explaining besides
the one already provided as comments in the `Makefile` itself.

After you're done with the `Makefile`, simply run `make <target>`,
in which target is one of:
* `libaes.a`: For a static library.
* `libaes.so`: For a shared (dynamic) object.
* `all`: For both `libaes.a` and `libaes.so`.
