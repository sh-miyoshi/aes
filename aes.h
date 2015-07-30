#pragma once

#include <string>
#include <wmmintrin.h>

class AES{
	int ROUND_NUM;
	__m128i bkey;

	__m128i GetBinaryKey(std::string key);
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
