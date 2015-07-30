#pragma once

#include <stdio.h>
#include <string>

class AES{
	static const int BLOCK_SIZE=16;// 128/8

	unsigned char *roundKey;
	int ROUND_NUM,WORD_KEY_LENGTH;

	void GetBinaryData(unsigned char *ret,std::string *data);
	std::string GetStringData(const unsigned char *buf,int size);
	void GetBinaryKey(unsigned char *ret,std::string key);

	unsigned char ExtMul(unsigned char data,int n);
	void SubWord(unsigned char *w);
	void RotWord(unsigned char *w);
	void KeyExpansion(unsigned char *key);

	void SubBytes(unsigned char *data);
	void ShiftRows(unsigned char *data);
	void MixColumns(unsigned char *data);
	void InvSubBytes(unsigned char *data);
	void InvShiftRows(unsigned char *data);
	void InvMixColumns(unsigned char *data);
	void AddRoundKey(unsigned char *data,int n);
public:
	enum Type{
		TYPE_128,
		TYPE_192,
		TYPE_256
	};

	AES(Type type,std::string key);
	~AES();

	std::string Encrypt(std::string data);
	std::string Decrypt(std::string data);
};
