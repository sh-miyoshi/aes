#include "aes.h"
#include <stdio.h>

int main() {
    std::string input_fname = "README.md";
    std::string encrypt_fname = "test_enc.dat";
    std::string result_fname = "result.md";

    unsigned char iv[16]; // initialize vector
    // please set secure key
    unsigned char key[16] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };
    aes::AES::GenerateIV(iv, aes::AES_ECB);

    // printf("iv: (");
    // for (int i = 0; i < 16; i++) {
    //     printf("%d", iv[i]);
    //     if (i < 15) {
    //         printf(", ");
    //     }
    // }
    // puts(")");

    // create handler with 128-bit key length, cbc mode, (padding is PSCK#5)
    aes::AES handler(aes::AES_CBC, key, 128, iv);

    // Encryption
    aes::Error err = handler.Encrypt(input_fname, encrypt_fname);
    if (!err.success) {
        printf("Failed to encrypt: %s\n", err.message.c_str());
        return 1;
    }

    // Decryption
    err = handler.Decrypt(encrypt_fname, result_fname);
    if (!err.success) {
        printf("Failed to decrypt: %s\n", err.message.c_str());
        return 1;
    }
}
