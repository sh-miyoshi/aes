#pragma once

#include <string>
#include <wmmintrin.h>

// Please set USE_AES_NI to 1, if you want to use hardware accelerator.
#define USE_AES_NI 1
// #define USE_AES_NI 0

// FILE_READ_SIZE is a read byte size from file at once
#define FILE_READ_SIZE (65536)

#define AES_BLOCK_SIZE (16)

namespace aes {
enum Mode {
    AES_ECB,
    AES_CBC,
    AES_CTR,
};

enum PaddingMode {
    PADDING_ZERO,
    PADDING_PKCS_5,
};

class Error {
  public:
    bool success;
    std::string message;

    Error() : success(true) {}
    ~Error() {}
};

class AES {
    static const unsigned int MAX_NR = 14; // max no of rounds

    unsigned int Nr; // number of rounds
    Error initError;
    Mode mode;
    PaddingMode paddingMode;

    void Init(Mode mode, const unsigned char *key, unsigned int keyBitLen, unsigned char *iv);
    void SetPadding(char *data, int size);
    int GetDataSizeWithoutPadding(const char *data);
    Error FileOpen(FILE **fp, std::string fname, std::string mode);
#if USE_AES_NI
    __m128i encKey[MAX_NR + 2], decKey[MAX_NR + 2];
    __m128i iv, vec;
    __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2);
    void AES_192_ASSIST(__m128i &temp1, __m128i &temp2, __m128i &temp3);
    void AES_256_ASSIST_1(__m128i &temp1, __m128i &temp2);
    void AES_256_ASSIST_2(__m128i &temp1, __m128i &temp3);
    void AES_128_Key_Expansion(__m128i *key, const unsigned char *userKey);
    void AES_192_Key_Expansion(__m128i *key, const unsigned char *userKey);
    void AES_256_Key_Expansion(__m128i *key, const unsigned char *userKey);

    __m128i EncryptCore(__m128i data);
    __m128i DecryptCore(__m128i data);
#else
    unsigned char iv[AES_BLOCK_SIZE]; // initialize vector
    unsigned char vec[AES_BLOCK_SIZE];
    unsigned char roundKey[AES_BLOCK_SIZE * (MAX_NR + 1)];

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

    void EncryptCore(unsigned char *data);
    void DecryptCore(unsigned char *data);
#endif
  public:
    // generate initialize vector
    static void GenerateIV(unsigned char *iv, Mode mode);
    static void GenerateIV(unsigned char *iv, std::string passpharse, Mode mode);

    AES(const unsigned char *key, unsigned int keyBitLen);
    AES(Mode mode, const unsigned char *key, unsigned int keyBitLen, unsigned char *iv);
    ~AES() {}

    void SetPaddingMode(PaddingMode mode) { this->paddingMode = mode; }

    Error Encrypt(std::string in_fname, std::string out_fname);
    Error Decrypt(std::string in_fname, std::string out_fname);
};
}; // namespace aes
