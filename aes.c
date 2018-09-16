#include "aes.h"	/* For AES types 		*/
#include <stdlib.h>	/* For malloc() and free()	*/

/* S-Boxes are 16x16 substitution matrices for mapping bytes 1:1, the
 * particular S-Box used in the AES algorythm is called the Rijndael
 * S-Box (See https://en.wikipedia.org/wiki/Rijndael_S-box), and,
 * while the implementation allows for custom S-Boxes to be used, by
 * default, these are the two boxes used respectively in encryption
 * and decryption. */
static const unsigned char DEF_FSBOX[] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
static const unsigned char DEF_RSBOX[] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* Key-Block-Round triplets for supported key lengths.
 * Note that this is not enforced. The implementation will accept
 * any KBR triplet. However, none outside of these values have any
 * guarantee of security or correctness. */
static const struct{
	unsigned int keylen;
	unsigned int block_size;
	unsigned int rounds;
} KBR_TABLE[] = {
	{4, 4, 10},
	{6, 4, 12},
	{8, 4, 14}
};

/* Rotate a word to the left */
void
wrot(aes_word *w)
{
	unsigned char a0;
	a0 = (*w & 0xff000000) >> 24;

	*w <<= 8;
	*w |= a0;
}

/* Rotate a word to the right */
void
rwrot(aes_word *w)
{
	unsigned int a3;
	a3 = *w & 0xff;

	*w >>= 8;
	*w |= a3 << 24;
}

/* Substitute a word using a given S-Box */
void
wsbt(aes_word *w, unsigned const char* sbox)
{
	unsigned char *i;
	for(i = (unsigned char*) w; (char*)i < (char*)w + sizeof(int); ++i)
		*i = sbox[*i];
}

/* This is the heart of the algorythm. To every input block is applied,
 * sequentially, a given groups of blocks derived from the key, 
 * collectively called the Key Schedule. This function implements the
 * algorythm responsible for deriving the Key Schedule from a given key,
 * the so called Key Expantion procedure.
 */
void
keyexpand(
	union aes_keyexpand e,
	unsigned char keylen,
	unsigned char rounds,
	unsigned char block_size,
	unsigned int  *key,
	unsigned const char *sbox)
{
	unsigned int i;
	/* Copy keylen words over */
	for(i = 0; i < keylen; ++i)
		e.words[i] = key[i];
	
	/* Generate remaining words */
	for(; i < block_size * rounds; ++i){
		unsigned int prev = e.words[i - 1];
		if(i % keylen == 0){
			wrot(&prev);
			wsbt(&prev, sbox);
			prev ^= 0x01000000 << (i / keylen - 1);
		} else if(keylen > 6 && i % keylen == 4)
			wsbt(&prev, sbox);
		e.words[i] = e.words[i - keylen] ^ prev;
	}
}

/* Convenience function for XOR'ing words in batches */
void
xorblk(
	unsigned char block_size,
	aes_word *a, aes_word *b)
{
	unsigned char i;
	for(i = 0; i < block_size; ++i)
		a[i] ^= b[i];
}

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
	void *key)
{
	/* Use default S-Boxes if none were provided */
	if(fsbox == NULL || rsbox == NULL){
		t->fsbox = DEF_FSBOX;
		t->rsbox = DEF_RSBOX;
	}else{
		t->fsbox = fsbox;
		t->rsbox = rsbox;
	}
	
	/* Expand key */
	union aes_keyexpand ex;
	ex.bytes = malloc(sizeof(aes_word) * block_size * (rounds + 1));
	keyexpand(ex, keylen, rounds, block_size, key, t->fsbox);

	/* Initialize structure */
	t->keylen = keylen;
	t->rounds = rounds;
	t->block_size = block_size;
	t->keyexpand = ex;	
}

/* Frees data previously allocated for an AES state */
void
aes_free(struct aes *t)
{
	/* Free expanded key */
	free(t->keyexpand.bytes);
}

/* Performs batch substitution of bytes using a given S-Box */
void
sbtblk(
	unsigned char block_size,
	unsigned char *block,
	unsigned const char* sbox)
{
	unsigned int i;
	for(i = 0; i < block_size * sizeof(aes_word); ++i)
		block[i] = sbox[block[i]];
}

/* Performs a right rotation on a block where every row is
 * rotated right by y times, where y is the current row coord. */
void
rrtblk(
	unsigned char width,
	unsigned char height,
	unsigned char *m)
{	
	unsigned int x, y, r;
	for(y = 1; y < height; ++y){
		/* For every row, perform the shift y times */
		for(r = 0; r < y; ++r){
			/* Since this is a right shift, save the rightmost
			 * byte to be inserted in the leftmost position later. */
			unsigned char last;
			last = m[(width - 1) * height + y];
			
			/* Substitute right to left */
			for(x = width - 1; x > 0; --x){
				unsigned char a;
				a = m[(x - 1) * height + y];

				m[x * height + y] = a;
			}

			/* Put the saved character in the leftmost position. */
			m[y] = last;
		}
	}
}

/* Performs a left rotation on a block where every row is
 * rotated left by y times, where y is the current row coord. */
void
lrtblk(
	unsigned char width,
	unsigned char height,
	unsigned char *m)
{	
	unsigned int x, y, r;
	for(y = 1; y < height; ++y){
		/* For every row, perform the shift y times */
		for(r = 0; r < y; ++r){
			/* Since this is a left shift, save the lefttmost
			 * byte to be inserted in the rightmost position later. */
			unsigned char first;
			first = m[y];
			
			/* Substitute left to right */
			for(x = 0; x < width - 1; ++x){
				unsigned char a;
				a = m[(x + 1) * height + y];

				m[x * height + y] = a;
			}

			/* Put the saved character in the rightmost position. */
			m[(width - 1) * height + y] = first;
		}
	}
}

/* Performs multiplication in the [tfw no]GF(2 exp 8) field. */
unsigned char
ffpm(unsigned char a, unsigned char b)
{
	/* Accumulator for the product */
	unsigned char p;
	p = 0;

	unsigned char i;
	for(i = 0; i < 8; ++i){
		/* Check if there are pendencies */
		if(!a || !b) break;

		/* Perform multiplication based on the Peasent's Algorythm */
		if(b & 1) p ^= a;
		b >>= 1;
		
		unsigned char carry;
		carry = a & 0x80;
		
		a <<= 1;
		if(carry) a ^= 0x1b;
	}

	return p;
}

/* Encrypts a block state->block_size words long. */
void
aes_perform(struct aes *state, aes_word *input)
{
	/* XOR the initial round key */
	xorblk(state->block_size, input, state->keyexpand.words);
	
	unsigned int i, j;
	for(i = 1; i < state->rounds; ++i){
		sbtblk(state->block_size, input, state->fsbox);
		lrtblk(state->block_size, sizeof(aes_word), input);
		
		/* Mix columns forward */
		for(j = 0; j < state->block_size; ++j){
			union
			{
				aes_word w;
				unsigned char b[sizeof(aes_word)];
			} a, b;
			
			a.w = input[j];
			b.b[0] = ffpm(2, a.b[0]) ^ ffpm(3, a.b[1]) ^ ffpm(1, a.b[2]) ^ ffpm(1, a.b[3]);
			b.b[1] = ffpm(1, a.b[0]) ^ ffpm(2, a.b[1]) ^ ffpm(3, a.b[2]) ^ ffpm(1, a.b[3]);
			b.b[2] = ffpm(1, a.b[0]) ^ ffpm(1, a.b[1]) ^ ffpm(2, a.b[2]) ^ ffpm(3, a.b[3]);
			b.b[3] = ffpm(3, a.b[0]) ^ ffpm(1, a.b[1]) ^ ffpm(1, a.b[2]) ^ ffpm(2, a.b[3]);

			input[j] = b.w;
		}
		
		/* XOR sheduled key for the current round */
		xorblk(state->block_size, input, &state->keyexpand.words[i * state->block_size]);
	}

	sbtblk(state->block_size, input, state->fsbox);
	lrtblk(state->block_size, sizeof(aes_word), input);

	/* XOR last remaining round key */
	xorblk(state->block_size, input, &state->keyexpand.words[i * state->block_size]);
}

/* Decrypts a block state->block_size words long */
void
aes_reverse(struct aes *state, aes_word *input)
{
	unsigned int i, j;
	i = state->rounds;

	/* XOR the last round key */
	xorblk(state->block_size, input, &state->keyexpand.words[i * state->block_size]);
	
	for(i = i - 1; i > 0; --i){
		rrtblk(state->block_size, sizeof(aes_word), input);
		sbtblk(state->block_size, input, state->rsbox);
			
		/* XOR scheduled key for the current round */
		xorblk(state->block_size, input, &state->keyexpand.words[i * state->block_size]);

		/* Mix columns in reverse */
		for(j = 0; j < state->block_size; ++j){
			union
			{
				aes_word w;
				unsigned char b[sizeof(aes_word)];
			} a, b;
			
			a.w = input[j];
			b.b[0] = ffpm(0xe, a.b[0]) ^ ffpm(0xb, a.b[1]) ^ ffpm(0xd, a.b[2]) ^ ffpm(0x9, a.b[3]);
			b.b[1] = ffpm(0x9, a.b[0]) ^ ffpm(0xe, a.b[1]) ^ ffpm(0xb, a.b[2]) ^ ffpm(0xd, a.b[3]);
			b.b[2] = ffpm(0xd, a.b[0]) ^ ffpm(0x9, a.b[1]) ^ ffpm(0xe, a.b[2]) ^ ffpm(0xb, a.b[3]);
			b.b[3] = ffpm(0xb, a.b[0]) ^ ffpm(0xd, a.b[1]) ^ ffpm(0x9, a.b[2]) ^ ffpm(0xe, a.b[3]);

			input[j] = b.w;
		}

	}

		
	sbtblk(state->block_size, input, state->rsbox);
	rrtblk(state->block_size, sizeof(aes_word), input);

	/* XOR initial round key */
	xorblk(state->block_size, input,  state->keyexpand.words);

}
