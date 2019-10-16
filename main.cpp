#ifndef _WINDOWS
#if defined(_WIN64) || defined(_WIN32) || defined(__MINGW32__) || defined(__MINGW64__)
#define _WINDOWS
#endif
#endif

#include "aes.h"
#include "option.h"
#include <iostream>
#include <stdio.h>
#include <time.h>

#ifdef _WINDOWS
#include <conio.h>
#else
#include <unistd.h>
#endif

// #define TIME_MEASUREMENT

enum RunMode {
    RUN_UNDEFINED,
    RUN_ENCRYPT,
    RUN_DECRYPT,
};

std::string InputSecretData(std::string prefix);

int main(int argc, char *argv[]) {
    // Define Options
    option::OpsParse opt;
    // TODO(command name argv[0]?)
    opt.AddHelpMessage("aes.exe (--enc or --dec) [options] <input-file-name> <output-file-name>");
    opt.AddDefine("--enc", "", false, "Run as Encryption mode");
    opt.AddDefine("--dec", "", false, "Run as Decryption mode");
    opt.AddDefine("-m", "--mode", true, "AES mode (ecb, cbc, ctr) default: ctr");
    opt.AddDefine("-p", "--password", true, "pass pharse of secret key");
    opt.AddDefine("-l", "--key-len", true, "AES key length (128, 192, 256) default: 256");
    opt.AddDefine("--padding", "", true, "padding mode of AES (zero, pkcs5), ignored if CTR mode default: pkcs5");
    opt.AddDefine("-?", "--help", false, "show this help message");

    if (!opt.ParseArguments(argc, argv)) {
        std::cerr << "Failed to parse optioons" << std::endl;
        opt.ShowHelpMessage();
        return 1;
    }

    // Set default value to variables
    RunMode runMode = RUN_UNDEFINED;
    aes::Mode aesMode = aes::AES_CTR;
    unsigned int keyLen = 256;
    std::string passpharse;

    // Check command line options
    for (auto opt_none : opt.GetOptionNone()) {
        if (opt_none == "-?" || opt_none == "--help") {
            opt.ShowHelpMessage();
            return 0;
        } else if (opt_none == "--enc") {
            if (runMode == RUN_UNDEFINED) {
                runMode = RUN_ENCRYPT;
            } else {
                std::cerr << "Please input --enc or --dec" << std::endl;
                return 1;
            }
        } else if (opt_none == "--dec") {
            if (runMode == RUN_UNDEFINED) {
                runMode = RUN_DECRYPT;
            } else {
                std::cerr << "Please input --enc or --dec" << std::endl;
                return 1;
            }
        }
    }
    if (runMode == RUN_UNDEFINED) {
        std::cerr << "Please input --enc or --dec" << std::endl;
        return 1;
    }

    for (auto opt_val : opt.GetOptionValue()) {
        if (opt_val.first == "-l" || opt_val.first == "--key-len") {
            keyLen = atoi(opt_val.second.c_str());
        } else if (opt_val.first == "-p" || opt_val.first == "--password") {
            passpharse = opt_val.second;
        } else if (opt_val.first == "-m" || opt_val.first == "--mode") {
            if (opt_val.second == "ecb") {
                aesMode = aes::AES_ECB_PKCS_5;
            } else if (opt_val.second == "cbc") {
                aesMode = aes::AES_CBC_PKCS_5;
            } else if (opt_val.second == "ctr") {
                aesMode = aes::AES_CTR;
            } else {
                std::cerr << "Unknown mode <" << opt_val.second << "> was given." << std::endl;
                return 1;
            }
        } else if (opt_val.first == "--padding") {
            if (opt_val.second == "zero") {
                if (aesMode == aes::AES_CBC_PKCS_5)
                    aesMode = aes::AES_CBC_ZERO;
                if (aesMode == aes::AES_ECB_PKCS_5)
                    aesMode = aes::AES_ECB_ZERO;
            } else if (opt_val.second != "pkcs5") {
                std::cerr << "Unknown padding mode <" << opt_val.second << "> was given." << std::endl;
                return 1;
            }
        }
    }

    auto args = opt.GetArgs();
    if (args.size() != 2) {
        std::cerr << "Plaese input <input-file-name> and <output-file-name>" << std::endl;
        return 1;
    }

    // Set passpharse from STDIN
    if (passpharse.empty()) {
        passpharse = InputSecretData("Password: ");
    }

    // Generate AES key and iv from passpharse
    unsigned char iv[16];
    aes::AES::GenerateIV(iv, passpharse, aesMode);
    unsigned char key[32];
    for (int i = 0; i < keyLen / 8; i++) {
        key[i] = (unsigned char)passpharse[i % passpharse.size()];
    }

#ifdef TIME_MEASUREMENT
    clock_t start_time = clock();
#endif

    // Run AES
    aes::AES handler(aesMode, key, keyLen, iv);

    if (runMode == RUN_ENCRYPT) {
        handler.Encrypt(args[0], args[1]);
    } else if (runMode == RUN_DECRYPT) {
        handler.Decrypt(args[0], args[1]);
    }

#ifdef TIME_MEASUREMENT
    clock_t end_time = clock();
    printf("%.2f[sec]\n", (double)(end_time - start_time) / CLOCKS_PER_SEC);
#endif
    return 0;
}

std::string InputSecretData(std::string prefix) {
#ifdef _WINDOWS
    std::string res;
    std::cout << prefix;
    char c;
    while ((c = getch()) != '\n' && c != '\r') {
        if (c == '\b') { // BackSpace
            if (!res.empty()) {
                printf("\b \b");
                res.erase(res.size() - 1);
            }
        } else if (c < 0x20 || c > 0x7e) { // 2byte character in Shift-JIS
            getch();
        } else if (c != '\t' && c != 0x1b) { // Tab,Esc?
            putchar('*');
            res += c;
        }
    }
    putchar('\n');
    return res;
#else
    return getpass(prefix.c_str());
#endif
}