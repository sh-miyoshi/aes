/*#include <iostream>
#include <stdlib.h>
#include "aes.h"
using namespace std;

static __m128i AES_128_ASSIST(__m128i temp1,__m128i temp2){
	__m128i temp3;
	temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
	temp3 = _mm_slli_si128 (temp1, 0x4);
	temp1 = _mm_xor_si128 (temp1, temp3);
	temp3 = _mm_slli_si128 (temp3, 0x4);
	temp1 = _mm_xor_si128 (temp1, temp3);
	temp3 = _mm_slli_si128 (temp3, 0x4);
	temp1 = _mm_xor_si128 (temp1, temp3);
	temp1 = _mm_xor_si128 (temp1, temp2);
	return temp1;
}

static void AES_128_Key_Expansion(__m128i *key,const unsigned char *userkey){
	__m128i temp1, temp2;
	temp1 = _mm_loadu_si128((__m128i*)userkey);
	key[0] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
	temp1 = AES_128_ASSIST(temp1, temp2);
	key[1] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
	temp1 = AES_128_ASSIST(temp1, temp2);
	key[2] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
	temp1 = AES_128_ASSIST(temp1, temp2);
	key[3] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
	temp1 = AES_128_ASSIST(temp1, temp2);
	key[4] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
	temp1 = AES_128_ASSIST(temp1, temp2);
	key[5] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
	temp1 = AES_128_ASSIST(temp1, temp2);
	key[6] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
	temp1 = AES_128_ASSIST(temp1, temp2);
	key[7] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
	temp1 = AES_128_ASSIST(temp1, temp2);
	key[8] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
	temp1 = AES_128_ASSIST(temp1, temp2);
	key[9] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
	temp1 = AES_128_ASSIST(temp1, temp2);
	key[10] = temp1;
}

void AES_Setup(__m128i *enc_key,__m128i *dec_key,std::string user_key){
	unsigned char uk[16]={0};
	for(int i=0;i<16;i++)
		uk[i]=user_key[i%user_key.size()];
	AES_128_Key_Expansion(enc_key,uk);
	for(int i=0;i<10;i++)
		dec_key[10-i]=_mm_aesimc_si128(enc_key[i]);
	dec_key[0]=enc_key[10];
}

__m128i AES_Encrypt(__m128i data,__m128i *enc_key){
	data=_mm_xor_si128(data,enc_key[0]);
	for(int i=1;i<10;i++)
		data=_mm_aesenc_si128(data,enc_key[i]);
	return _mm_aesenclast_si128(data,enc_key[10]);
}

__m128i AES_Decrypt(__m128i data,__m128i *dec_key){
	data=_mm_xor_si128(data,dec_key[0]);
	for(int i=1;i<10;i++)
		data=_mm_aesdec_si128(data,dec_key[i]);
	return _mm_aesdeclast_si128(data,dec_key[10]);
}
*/

#include "aes.h"
#include <assert.h>

static __m128i AES_128_ASSIST (__m128i temp1, __m128i temp2)
{
    __m128i temp3;
    temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
    temp3 = _mm_slli_si128 (temp1, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp1 = _mm_xor_si128 (temp1, temp2);
    return temp1;
}

static void AES_128_Key_Expansion (unsigned char *userkey, __m128i *key)
{
    __m128i temp1, temp2;
    temp1 = _mm_loadu_si128((__m128i*)userkey);
    key[0] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[4] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[10] = temp1;
}

void aes_setup(AESContext * ctx, unsigned char *key, int keylen)
{
    unsigned int unalignment = (size_t)ctx % 16;
    ctx->offset = unalignment ? 16 - unalignment : 0;
    __m128i *keysched = (__m128i*)((unsigned char*)ctx->keysched + ctx->offset);
    __m128i *invkeysched = (__m128i*)((unsigned char*)ctx->invkeysched + ctx->offset);

    ctx->Nr = 6 + (keylen / 4); /* Number of rounds */
    invkeysched += ctx->Nr;

    /*
     * Now do the key setup itself.
     */
    switch (keylen)
    {
    case 16:
        AES_128_Key_Expansion (key, keysched);
        break;
    default:
        assert(0);
    }

    /*
     * Now prepare the modified keys for the inverse cipher.
     */
    *invkeysched = *keysched;
    switch (ctx->Nr)
    {
    case 10:
        *(--invkeysched) = _mm_aesimc_si128(*(++keysched));
        *(--invkeysched) = _mm_aesimc_si128(*(++keysched));
        *(--invkeysched) = _mm_aesimc_si128(*(++keysched));
        *(--invkeysched) = _mm_aesimc_si128(*(++keysched));
        *(--invkeysched) = _mm_aesimc_si128(*(++keysched));
        *(--invkeysched) = _mm_aesimc_si128(*(++keysched));
        *(--invkeysched) = _mm_aesimc_si128(*(++keysched));
        *(--invkeysched) = _mm_aesimc_si128(*(++keysched));
        *(--invkeysched) = _mm_aesimc_si128(*(++keysched));
    default:
        *(--invkeysched) = *(++keysched);
    }
}

void aes_encrypt_cbc(unsigned char *blk, int len, AESContext * ctx)
{
    __m128i enc;
    __m128i* block = (__m128i*)blk;
    const __m128i* finish = (__m128i*)(blk + len);

    assert((len & 15) == 0);

    /* Load IV */
    enc = _mm_loadu_si128((__m128i*)(ctx->iv));
    while (block < finish)
    {
        /* Key schedule ptr   */
        __m128i* keysched = (__m128i*)((unsigned char*)ctx->keysched + ctx->offset);

        /* Xor data with IV */
        enc  = _mm_xor_si128(_mm_loadu_si128(block), enc);

        /* Perform rounds */
        enc  = _mm_xor_si128(enc, *keysched);
        switch (ctx->Nr)
        {
        case 10:
            enc = _mm_aesenc_si128(enc, *(++keysched));
            enc = _mm_aesenc_si128(enc, *(++keysched));
            enc = _mm_aesenc_si128(enc, *(++keysched));
            enc = _mm_aesenc_si128(enc, *(++keysched));
            enc = _mm_aesenc_si128(enc, *(++keysched));
            enc = _mm_aesenc_si128(enc, *(++keysched));
            enc = _mm_aesenc_si128(enc, *(++keysched));
            enc = _mm_aesenc_si128(enc, *(++keysched));
            enc = _mm_aesenc_si128(enc, *(++keysched));
            enc = _mm_aesenclast_si128(enc, *(++keysched));
            break;
        default:
            assert(0);
        }

        /* Store and go to next block */
        _mm_storeu_si128(block, enc);
        ++block;
    }

    /* Update IV */
    _mm_storeu_si128((__m128i*)(ctx->iv), enc);
}

void aes_decrypt_cbc(unsigned char *blk, int len, AESContext * ctx)
{
    __m128i dec, last, iv;
    __m128i* block = (__m128i*)blk;
    const __m128i* finish = (__m128i*)(blk + len);

    assert((len & 15) == 0);

    /* Load IV */
    iv = _mm_loadu_si128((__m128i*)(ctx->iv));
    while (block < finish)
    {
        /* Key schedule ptr   */
        __m128i* keysched = (__m128i*)((unsigned char*)ctx->invkeysched + ctx->offset);
        last = _mm_loadu_si128(block);
        dec  = _mm_xor_si128(last, *keysched);
        switch (ctx->Nr)
        {
        case 14:
            dec = _mm_aesdec_si128(dec, *(++keysched));
            dec = _mm_aesdec_si128(dec, *(++keysched));
        case 12:
            dec = _mm_aesdec_si128(dec, *(++keysched));
            dec = _mm_aesdec_si128(dec, *(++keysched));
        case 10:
            dec = _mm_aesdec_si128(dec, *(++keysched));
            dec = _mm_aesdec_si128(dec, *(++keysched));
            dec = _mm_aesdec_si128(dec, *(++keysched));
            dec = _mm_aesdec_si128(dec, *(++keysched));
            dec = _mm_aesdec_si128(dec, *(++keysched));
            dec = _mm_aesdec_si128(dec, *(++keysched));
            dec = _mm_aesdec_si128(dec, *(++keysched));
            dec = _mm_aesdec_si128(dec, *(++keysched));
            dec = _mm_aesdec_si128(dec, *(++keysched));
            dec = _mm_aesdeclast_si128(dec, *(++keysched));
            break;
        default:
            assert(0);
        }

        /* Xor data with IV */
        dec  = _mm_xor_si128(iv, dec);

        /* Store data */
        _mm_storeu_si128(block, dec);
        iv = last;

        /* Go to next block */
        ++block;
    }

    /* Update IV */
    _mm_storeu_si128((__m128i*)(ctx->iv), dec);
}
