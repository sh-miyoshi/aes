@echo off
md tmp
make

aes.exe --enc -p test README.md tmp/encrypt.enc
aes.exe --dec -p test tmp/encrypt.enc tmp/result.md
fc /n README.md tmp/result.md

@PAUSE
