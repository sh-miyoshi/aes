@echo off

echo initalize process
md tmp
make

echo "test 128-bit, CBC, PKCS#5"
aes.exe --enc -p test -m cbc -l 128 --padding pkcs5 README.md tmp/encrypt.enc
aes.exe --dec -p test -m cbc -l 128 --padding pkcs5 tmp/encrypt.enc tmp/result.md
fc /n README.md tmp/result.md

echo "test 192-bit, CBC, PKCS#5"
aes.exe --enc -p test -m cbc -l 192 --padding pkcs5 README.md tmp/encrypt.enc
aes.exe --dec -p test -m cbc -l 192 --padding pkcs5 tmp/encrypt.enc tmp/result.md
fc /n README.md tmp/result.md

echo "test 256-bit, CBC, PKCS#5"
aes.exe --enc -p test -m cbc -l 256 --padding pkcs5 README.md tmp/encrypt.enc
aes.exe --dec -p test -m cbc -l 256 --padding pkcs5 tmp/encrypt.enc tmp/result.md
fc /n README.md tmp/result.md

echo "test 256-bit, CBC, ZERO"
aes.exe --enc -p test -m cbc -l 256 --padding zero README.md tmp/encrypt.enc
aes.exe --dec -p test -m cbc -l 256 --padding zero tmp/encrypt.enc tmp/result.md
fc /n README.md tmp/result.md

echo "test 256-bit, ECB, PKCS#5"
aes.exe --enc -p test -m ecb -l 256 --padding pkcs5 README.md tmp/encrypt.enc
aes.exe --dec -p test -m ecb -l 256 --padding pkcs5 tmp/encrypt.enc tmp/result.md
fc /n README.md tmp/result.md

@PAUSE
