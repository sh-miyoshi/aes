#include <stdio.h>
#include "aes.h"

int main() {
    unsigned char iv[16];
    unsigned char key[16] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };
    aes::AES::GenerateIV(iv, aes::AES_CTR);

    // printf("iv: (");
    // for (int i = 0; i < 16; i++) {
    //     printf("%d", iv[i]);
    //     if (i < 15) {
    //         printf(", ");
    //     }
    // }
    // puts(")");

    aes::AES handler(aes::AES_CTR, key, 128, iv);
    aes::Error err = handler.Encrypt("README.md", "tmp/enc.dat");
    if (!err.success) {
        printf("Failed to encrypt: %s\n", err.message.c_str());
        return 1;
    }
    err = handler.Decrypt("tmp/enc.dat", "tmp/result.md");
    if (!err.success) {
        printf("Failed to decrypt: %s\n", err.message.c_str());
        return 1;
    }
}
