#pragma once

#include <string>
#include <wmmintrin.h>

class AES{
	const int WORD_KEY_LENGTH,BYTE_KEY_LENGTH;
	const int ROUND_NUM;

	static const int ROUND_NUM_MAX=14;
	__m128i roundKey[ROUND_NUM_MAX+1];

	void SubWord(unsigned char *w);
	void RotWord(unsigned char *w);
	void GenerateRoundKey(std::string key);
public:
	enum Type{
		TYPE_128,
		TYPE_192,
		TYPE_256
	};

	AES(Type type,std::string key);
	~AES();

	__m128i Encrypt(__m128i data);
	__m128i Decrypt(__m128i data);
};
