#!/bin/bash

mkdir -p tmp
make

./aes --enc -p test README.md tmp/encrypt.enc
./aes --dec -p test tmp/encrypt.enc tmp/result.md

echo "---diff data---"
diff README.md tmp/result.md
echo "---diff end---"