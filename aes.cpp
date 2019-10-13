#include "aes.h"
#include <random>
#include <sstream>
using namespace aes;

#if !USE_AES_NI
static const unsigned char SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16
};

static const unsigned char INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d
};
#endif

void AES::GenerateIV(unsigned char *iv, Mode mode) {
    std::random_device rand_dev;

    if (mode == AES_CTR) {
        // [8bit nonce][8bit counter]
        for (int i = 0; i < 8; i++) {
            iv[i] = (unsigned char)rand_dev();
        }
        for (int i = 8; i < 15; i++) {
            iv[i] = 0;
        }
        iv[15] = 1;
    } else {
        // set all random data
        for (int i = 0; i < 16; i++) {
            iv[i] = (unsigned char)rand_dev();
        }
    }
}

AES::AES(const unsigned char *key, unsigned int keyBitLen) {
    // ECB mode is the only mode which does not use iv
    Init(AES_ECB, key, keyBitLen, nullptr);
}

AES::AES(Mode mode, const unsigned char *key, unsigned int keyBitLen, unsigned char *iv) {
    Init(mode, key, keyBitLen, iv);
}

void AES::Init(Mode mode, const unsigned char *key, unsigned int keyBitLen, unsigned char *iv) {
    this->mode = mode;

    unsigned int keyByteLen = keyBitLen / 8;  // maybe 16, 24, 32
    if (keyBitLen != 128 && keyBitLen != 192 && keyBitLen != 256) {
        initError.success = false;
        std::stringstream ss;
        ss << "Unexpected key length. ";
        ss << "AES just only support 128, 192, 256-bit, ";
        ss << "but got length: " << keyBitLen;
        initError.message = ss.str();
        return;
    }

    this->Nr = 6 + (keyByteLen / 4);
    unsigned char userKey[32];
    for (int i = 0; i < keyByteLen; i++) {
        userKey[i] = key[i];
    }

#if USE_AES_NI
    switch (keyBitLen) {
        case 128:
            AES_128_Key_Expansion(encKey, userKey);
            break;
        case 192:
            AES_192_Key_Expansion(encKey, userKey);
            break;
        case 256:
            AES_256_Key_Expansion(encKey, userKey);
            break;
    }

    decKey[Nr] = encKey[0];
    for (int i = 1; i < Nr; i++)
        decKey[Nr - i] = _mm_aesimc_si128(encKey[i]);
    decKey[0] = encKey[Nr];

    if (!iv) {
        this->vec = _mm_setzero_si128();
    } else {
        this->vec = _mm_loadu_si128((__m128i *)iv);
    }
#else
    // TODO(not implemented yet)
    initError.success = false;
    initError.message = "Sorry, aes without ardware accelerator is not implemented yet";
#endif
}

Error AES::Encrypt(std::string in_fname, std::string out_fname) {
    if (!initError.success) {
        return initError;
    }

    return Error();
}

Error AES::Decrypt(std::string in_fname, std::string out_fname) {
    if (!initError.success) {
        return initError;
    }

    return Error();
}

#if USE_AES_NI
__m128i AES::AES_128_ASSIST(__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp3 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp1 = _mm_xor_si128(temp1, temp2);
    return temp1;
}

void AES::AES_192_ASSIST(__m128i &temp1, __m128i &temp2, __m128i &temp3) {
    __m128i temp4;
    temp2 = _mm_shuffle_epi32(temp2, 0x55);
    temp4 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    temp1 = _mm_xor_si128(temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    temp1 = _mm_xor_si128(temp1, temp4);
    temp1 = _mm_xor_si128(temp1, temp2);
    temp2 = _mm_shuffle_epi32(temp1, 0xff);
    temp4 = _mm_slli_si128(temp3, 0x4);
    temp3 = _mm_xor_si128(temp3, temp4);
    temp3 = _mm_xor_si128(temp3, temp2);
}

void AES::AES_256_ASSIST_1(__m128i &temp1, __m128i &temp2) {
    __m128i temp4;
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp4 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    temp1 = _mm_xor_si128(temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    temp1 = _mm_xor_si128(temp1, temp4);
    temp1 = _mm_xor_si128(temp1, temp2);
}

void AES::AES_256_ASSIST_2(__m128i &temp1, __m128i &temp3) {
    __m128i temp2, temp4;
    temp4 = _mm_aeskeygenassist_si128(temp1, 0x0);
    temp2 = _mm_shuffle_epi32(temp4, 0xaa);
    temp4 = _mm_slli_si128(temp3, 0x4);
    temp3 = _mm_xor_si128(temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    temp3 = _mm_xor_si128(temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    temp3 = _mm_xor_si128(temp3, temp4);
    temp3 = _mm_xor_si128(temp3, temp2);
}

void AES::AES_128_Key_Expansion(__m128i *key, const unsigned char *userKey) {
    __m128i temp1 = _mm_loadu_si128((__m128i *)userKey), temp2;
    key[0] = temp1;
    for (int i = 1; i <= 10; i++) {
        switch (i) {
            case 1:
                temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
                break;
            case 2:
                temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
                break;
            case 3:
                temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
                break;
            case 4:
                temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
                break;
            case 5:
                temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
                break;
            case 6:
                temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
                break;
            case 7:
                temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
                break;
            case 8:
                temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
                break;
            case 9:
                temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
                break;
            case 10:
                temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
                break;
        }
        temp1 = AES_128_ASSIST(temp1, temp2);
        key[i] = temp1;
    }
}

void AES::AES_192_Key_Expansion(__m128i *key, const unsigned char *userKey) {
    __m128i temp1, temp2, temp3;
    temp1 = _mm_loadu_si128((__m128i *)userKey);
    temp3 = _mm_loadu_si128((__m128i *)(userKey + 16));
    for (int i = 0; i < 12; i += 3) {
        key[i] = temp1;
        key[i + 1] = temp3;
        switch (i) {
            case 0:
                temp2 = _mm_aeskeygenassist_si128(temp3, 0x1);
                break;
            case 3:
                temp2 = _mm_aeskeygenassist_si128(temp3, 0x4);
                break;
            case 6:
                temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
                break;
            case 9:
                temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
                break;
        }
        AES_192_ASSIST(temp1, temp2, temp3);
        key[i + 1] = (__m128i)_mm_shuffle_pd((__m128d)key[i + 1], (__m128d)temp1, 0);
        key[i + 2] = (__m128i)_mm_shuffle_pd((__m128d)temp1, (__m128d)temp3, 1);
        switch (i) {
            case 0:
                temp2 = _mm_aeskeygenassist_si128(temp3, 0x2);
                break;
            case 3:
                temp2 = _mm_aeskeygenassist_si128(temp3, 0x8);
                break;
            case 6:
                temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
                break;
            case 9:
                temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
                break;
        }
        AES_192_ASSIST(temp1, temp2, temp3);
    }
    key[12] = temp1;
    key[13] = temp3;
}

void AES::AES_256_Key_Expansion(__m128i *key, const unsigned char *userKey) {
    __m128i temp1, temp2, temp3;
    temp1 = _mm_loadu_si128((__m128i *)userKey);
    temp3 = _mm_loadu_si128((__m128i *)(userKey + 16));
    key[0] = temp1;
    key[1] = temp3;
    for (int i = 2; i <= 12; i += 2) {
        switch (i) {
            case 2:
                temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
                break;
            case 4:
                temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
                break;
            case 6:
                temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
                break;
            case 8:
                temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
                break;
            case 10:
                temp2 = _mm_aeskeygenassist_si128(temp3, 0x010);
                break;
            case 12:
                temp2 = _mm_aeskeygenassist_si128(temp3, 0x020);
                break;
        }
        AES_256_ASSIST_1(temp1, temp2);
        key[i] = temp1;
        AES_256_ASSIST_2(temp1, temp3);
        key[i + 1] = temp3;
    }
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
    AES_256_ASSIST_1(temp1, temp2);
    key[14] = temp1;
}

__m128i AES::OneRoundEncrypt(__m128i data) {
    switch (mode) {
        case AES_ECB:
            // Nothing to do
            break;
        case AES_CBC_ZERO:
        case AES_CBC_PKCS5:
            data = _mm_xor_si128(data, vec);
            break;
        case AES_CTR:
            break;
    }

    // Encrypt
    data = _mm_xor_si128(data, encKey[0]);
    for (int i = 1; i < Nr; i++) {
        data = _mm_aesenc_si128(data, encKey[i]);
    }

    switch (mode) {
        case AES_ECB:
            // Nothing to do
            break;
        case AES_CBC_ZERO:
        case AES_CBC_PKCS5:
            vec = data;
            break;
        case AES_CTR:
            break;
    }

    return _mm_aesenclast_si128(data, encKey[Nr]);
}

__m128i AES::OneRoundDecrypt(__m128i data) {
    __m128i prevVec = vec;
    switch (mode) {
        case AES_ECB:
            // Nothing to do
            break;
        case AES_CBC_ZERO:
        case AES_CBC_PKCS5:
            vec = data;
            break;
        case AES_CTR:
            break;
    }

    // Decrypt
    data = _mm_xor_si128(data, decKey[0]);
    for (int i = 1; i < Nr; i++) {
        data = _mm_aesdec_si128(data, decKey[i]);
    }
    data = _mm_aesdeclast_si128(data, decKey[Nr]);

    switch (mode) {
        case AES_ECB:
            // Nothing to do
            break;
        case AES_CBC_ZERO:
        case AES_CBC_PKCS5:
            data = _mm_xor_si128(data, prevVec);
            break;
        case AES_CTR:
            break;
    }

    return data;
}
#endif