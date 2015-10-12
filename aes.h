#pragma once

#include <string>
#include <wmmintrin.h>

//void AES_Setup(__m128i *enc_key,__m128i *dec_key,std::string user_key);
//__m128i AES_Encrypt(__m128i data,__m128i *enc_key);
//__m128i AES_Decrypt(__m128i data,__m128i *dec_key);

#define MAX_NR 14   /* max no of rounds */
#define NB 4        /* no of words in cipher blk */

typedef struct AESContext AESContext;

struct AESContext {
    unsigned int keysched[(MAX_NR + 2) * NB];
    unsigned int invkeysched[(MAX_NR + 2) * NB];
    unsigned int iv[NB];
    unsigned int Nr; /* number of rounds */
    unsigned int offset; /* offset for aligned key expansion */
};

void aes_setup(AESContext * ctx, unsigned char *key, int keylen);
void aes_encrypt_cbc(unsigned char *blk, int len, AESContext * ctx);
void aes_decrypt_cbc(unsigned char *blk, int len, AESContext * ctx);
