#!/bin/bash

echo "--- initialize process ---"
mkdir -p tmp
make
echo "--- finished initlization ---"

echo "test 128-bit, CTR"
./aes --enc -p test -m ctr -l 128 README.md tmp/encrypt.enc
./aes --dec -p test -m ctr -l 128 tmp/encrypt.enc tmp/result.md
diff README.md tmp/result.md

echo "test 192-bit, CTR"
./aes --enc -p test -m ctr -l 192 README.md tmp/encrypt.enc
./aes --dec -p test -m ctr -l 192 tmp/encrypt.enc tmp/result.md
diff README.md tmp/result.md

echo "test 256-bit, CTR"
./aes --enc -p test -m ctr -l 256 README.md tmp/encrypt.enc
./aes --dec -p test -m ctr -l 256 tmp/encrypt.enc tmp/result.md
diff README.md tmp/result.md


echo "test 128-bit, CBC, PKCS#5"
./aes --enc -p test -m cbc -l 128 --padding pkcs5 README.md tmp/encrypt.enc
./aes --dec -p test -m cbc -l 128 --padding pkcs5 tmp/encrypt.enc tmp/result.md
diff README.md tmp/result.md

echo "test 192-bit, CBC, PKCS#5"
./aes --enc -p test -m cbc -l 192 --padding pkcs5 README.md tmp/encrypt.enc
./aes --dec -p test -m cbc -l 192 --padding pkcs5 tmp/encrypt.enc tmp/result.md
diff README.md tmp/result.md

echo "test 256-bit, CBC, PKCS#5"
./aes --enc -p test -m cbc -l 256 --padding pkcs5 README.md tmp/encrypt.enc
./aes --dec -p test -m cbc -l 256 --padding pkcs5 tmp/encrypt.enc tmp/result.md
diff README.md tmp/result.md

echo "test 256-bit, CBC, ZERO"
./aes --enc -p test -m cbc -l 256 --padding zero README.md tmp/encrypt.enc
./aes --dec -p test -m cbc -l 256 --padding zero tmp/encrypt.enc tmp/result.md
diff README.md tmp/result.md

echo "test 256-bit, ECB, PKCS#5"
./aes --enc -p test -m ecb -l 256 --padding pkcs5 README.md tmp/encrypt.enc
./aes --dec -p test -m ecb -l 256 --padding pkcs5 tmp/encrypt.enc tmp/result.md
diff README.md tmp/result.md