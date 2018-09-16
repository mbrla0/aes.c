/* aes.h -- Pure C implementation of the AES
 * symmetrical cryptographic algorythm. */
#ifndef __AES_H__
#define __AES_H__

typedef unsigned int aes_word;
union aes_keyexpand
{
	unsigned char *bytes;
	aes_word *words;
};

struct aes
{
	/* Number of words in the key. */
	unsigned char keylen;

	/* Number of rounds to be performed */
	unsigned char rounds;

	/* Number of words per block */
	unsigned char block_size;

	/* Cypher keyexpand. Note that, even though this is large
	 * enough to hold a keyexpand for the maximum allowed length,
	 * only as many as aes->keylen * Nr (where Nr is the number of
	 * rounds matched with the current key length in aes.c) bytes
	 * will ever be filled and used.
	 */
	union aes_keyexpand keyexpand;
	
	/* Forward and Inverse, respectively, substitution boxes
	 * to be used in the cipher, laid out in a way such that,
	 * when indexed as [a * 16 + b], `a` reffers to the row
	 * and `b` to the column. */
	unsigned const char* fsbox;
	unsigned const char* rsbox;
};

/* Creates a new AES state, containing everything needed to both
 * encrypt and decrypt any message that utilizes the same combination
 * of key, KRB triplet, and forward and reverse S-Boxes. Note that
 * this function will allocate memory on the heap to store the Key
 * Schedule, and, therefore must be freed after use using aes_free().
 *
 * Note: If either S-Box pointer is NULL, the AES state will be
 * initaialized using the default, built-in  S-Boxes, namely, the
 * Rijndael S-Boxes. With the exception for some specific cases,
 * you`ll always just want to use the default S-Boxes.
 */
void
aes_new(
	struct aes *t,
	unsigned char keylen,
	unsigned char rounds,
	unsigned char block_size,
	unsigned const char *fsbox,
	unsigned const char *rsbox,
	void *key);

/* Frees data previously allocated for an AES state */
void
aes_free(struct aes *t);

/* Encrypts a block state->block_size words long. */
void
aes_perform(
	struct aes *state,
	aes_word *block);

/* Decrypts a block state->block_size words long */
void
aes_reverse(
	struct aes *state,
	aes_word *block);

#endif
