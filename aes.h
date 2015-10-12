#pragma once

#include <string>
#include <wmmintrin.h>

class AES{
	static const char MAX_NR=14;// max no of rounds
	__m128i enc_key[MAX_NR+2],dec_key[MAX_NR+2];
	unsigned char Nr;// number of rounds
	__m128i iv;// initialization vector

	__m128i AES_128_ASSIST(__m128i temp1,__m128i temp2);
	void AES_128_Key_Expansion(__m128i *key,const unsigned char *userKey);
public:
	enum Type{
		TYPE_128,
		TYPE_192,
		TYPE_256
	};

	AES(Type type,std::string key);
	~AES(){}

	__m128i Encrypt(__m128i data);
	__m128i Decrypt(__m128i data);

//	void Encrypt_CBC(unsigned char *enc,const unsigned char *data,int length);
//	void Decrypt_CBC(unsigned char *dec,const unsigned char *data,int length);
//	void Encrypt_CBC(FILE input);
};
