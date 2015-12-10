#pragma once

#include <string>
#include <wmmintrin.h>

class AES{
public:
	enum PaddingMode{
		PADDING_ZERO,
		PADDING_PKCS_5
	};
private:
	static const int MAX_NR=14;// max no of rounds
	static const int FILE_READ_SIZE=4096;

	__m128i enc_key[MAX_NR+2],dec_key[MAX_NR+2];
	unsigned int Nr;// number of rounds
	__m128i iv;// initialization vector

	__m128i AES_128_ASSIST(__m128i temp1,__m128i temp2);
	void AES_192_ASSIST(__m128i &temp1,__m128i &temp2,__m128i &temp3);
	void AES_256_ASSIST_1(__m128i &temp1,__m128i &temp2);
	void AES_256_ASSIST_2(__m128i &temp1,__m128i &temp3);
	void AES_128_Key_Expansion(__m128i *key,const unsigned char *user_key);
	void AES_192_Key_Expansion(__m128i *key,const unsigned char *user_key);
	void AES_256_Key_Expansion(__m128i *key,const unsigned char *user_key);

	int Padding(char *ret,PaddingMode mode,int val);
	void RemovePadding(FILE *fp_out,const char *buf,PaddingMode mode,int end_point);
public:
	AES(std::string key,unsigned int key_bit_length,const char *init_vec=NULL);
	~AES(){}

	__m128i Encrypt(__m128i data);
	__m128i Decrypt(__m128i data);

	void Encrypt(std::string in_fname,std::string out_fname,bool cbc,PaddingMode mode);
	void Decrypt(std::string in_fname,std::string out_fname,bool cbc,PaddingMode mode);
};
