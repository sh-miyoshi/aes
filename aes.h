#pragma once

#include <wmmintrin.h>
#include <string>

// Please set USE_AES_NI to 1, if you want to use hardware accelerator.
#define USE_AES_NI 1
// #define USE_AES_NI 0

// FILE_READ_SIZE is a read byte size from file at once
#define FILE_READ_SIZE 65536

namespace aes {
enum Mode {
    AES_ECB,
    AES_CBC_ZERO,
    AES_CBC_PKCS5,
    AES_CTR,
};

class Error {
   public:
    bool success;
    std::string message;

    Error() : success(true) {}
    ~Error() {}
};

class AES {
    static const unsigned int MAX_NR = 14;  // max no of rounds

    unsigned int Nr;  // number of rounds
    Error initError;
    Mode mode;

    // TODO(Padding, RemovePadding methods)
    void Init(Mode mode, const unsigned char *key, unsigned int keyBitLen, unsigned char *iv);
#if USE_AES_NI
    __m128i encKey[MAX_NR + 2], decKey[MAX_NR + 2];
    __m128i iv;  // initialization vector
    __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2);
    void AES_192_ASSIST(__m128i &temp1, __m128i &temp2, __m128i &temp3);
    void AES_256_ASSIST_1(__m128i &temp1, __m128i &temp2);
    void AES_256_ASSIST_2(__m128i &temp1, __m128i &temp3);
    void AES_128_Key_Expansion(__m128i *key, const unsigned char *userKey);
    void AES_192_Key_Expansion(__m128i *key, const unsigned char *userKey);
    void AES_256_Key_Expansion(__m128i *key, const unsigned char *userKey);

    __m128i OneRoundEncrypt(__m128i data);
    __m128i OneRoundDecrypt(__m128i data);
#else
    unsigned char iv[16];  // initialize vector
    unsigned char roundKey[16 * (MAX_NR + 1)];

    inline void ExtMul(unsigned char &x, unsigned char data, int n);
    void SubWord(unsigned char *w);
    void RotWord(unsigned char *w);
    void KeyExpansion(const unsigned char *userKey, int wordkeyBitLength);

    inline void SubBytes(unsigned char *data);
    inline void ShiftRows(unsigned char *data);
    inline void MixColumns(unsigned char *data);
    inline void InvSubBytes(unsigned char *data);
    inline void InvShiftRows(unsigned char *data);
    inline void InvMixColumns(unsigned char *data);
    inline void AddRoundKey(unsigned char *data, int n);

    void OneRoundEncrypt(unsigned char *data);
    void OneRoundDecrypt(unsigned char *data);
#endif
   public:
    // generate initialize vector
    static void GenerateIV(unsigned char *iv, Mode mode);

    AES(const unsigned char *key, unsigned int keyBitLen);
    AES(Mode mode, const unsigned char *key, unsigned int keyBitLen, unsigned char *iv);
    ~AES() {}

    Error Encrypt(std::string in_fname, std::string out_fname);
    Error Encrypt(std::string in_message, std::string *out_message);
    Error Decrypt(std::string in_fname, std::string out_fname);
    Error Decrypt(std::string in_message, std::string *out_message);
};
};  // namespace aes
