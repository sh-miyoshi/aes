# AES Library

## 概要

このリポジトリではc++実装によるAESのライブラリとそれを用いたファイル暗号化プログラムを公開しています。

## 使い方(プログラム編)

- windowsの場合
  - ブラウザから[https://github.com/sh-miyoshi/AES/releases/download/v2.0/aes.exe](https://github.com/sh-miyoshi/AES/releases/download/v2.0/aes.exe)にアクセス
  - aes.exeを任意の場所の保存
  - コマンドプロンプトを開き、以下を実行

  ```bash
  # 暗号化の場合
  ./aes.exe --enc input.txt encrypt.dat

  # 復号の場合
  ./aes.exe --dec encrypt.dat output.txt
  ```

- Linuxの場合
  - コマンドラインで以下を実行する

  ```bash
  wget https://github.com/sh-miyoshi/AES/releases/download/v2.0/aes
  chmod +x aes

  # 暗号化の場合
  ./aes --enc input.txt encrypt.dat

  # 復号の場合
  ./aes --dec encrypt.dat output.txt
  ```

## 使い方(ライブラリ編)

`aes.h`と`aes.cpp`を自身のプログラムに加えていただくだけです。  

### 使用例

```cpp
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
```

## プログラムに関して

__!!!注意点!!!__  
このプログラムにはパスフレーズからAESのIVを生成する場所にセキュアでない場所があります。  
また、実行中のメモリ状態まで意識して開発していないので本当にセキュアな実装が必要な場合は使用しないでください。

ハードウェアアクセラレーター(AES NI命令)が使用できない場合は`aes.h`の以下の場所を変更してください。

```cpp
#define USE_AES_NI 1 // 変更前
// ↓
#define USE_AES_NI 0 // 変更後
```

## 著者

Shunsuke Miyoshi

## ライセンス

このプログラムはMITライセンスでリリースされています。  
詳細は[ライセンスファイル](./LICENSE)を参照してください。
