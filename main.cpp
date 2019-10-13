#include <stdio.h>
#include "aes.h"

int main() {
    unsigned char iv[16];
    unsigned char key[16] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };
    std::string planeText = "secret texts";
    std::string encMsg;

    aes::AES::GenerateIV(iv, aes::AES_CTR);
    aes::AES handler(aes::AES_CTR, key, 128, iv);
    aes::Error err = handler.Encrypt(planeText, &encMsg);
    if (!err.success) {
        printf("Failed to encypt: %s\n", err.message.c_str());
    }

    printf("iv: (");
    for (int i = 0; i < 16; i++) {
        printf("%d", iv[i]);
        if (i < 15) {
            printf(", ");
        }
    }
    puts(")");
}
