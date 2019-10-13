#include <stdio.h>
#include "aes.h"

int main() {
    unsigned char iv[16];
    unsigned char key[16] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };
    std::string plainText = "This is a secret texts which you want to encrypt.";
    std::string encMsg, decMsg;

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
    aes::Error err = handler.Encrypt(plainText, &encMsg);
    if (!err.success) {
        printf("Failed to encrypt: %s\n", err.message.c_str());
    }
    err = handler.Decrypt(encMsg, &decMsg);
    if (!err.success) {
        printf("Failed to decrypt: %s\n", err.message.c_str());
    }

    printf("plain  : %s\n", plainText.c_str());
    printf("encrypt: %s\n", encMsg.c_str());
    printf("decrypt: %s\n", decMsg.c_str());
}
