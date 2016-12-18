#pragma once

#include <string>
#include <wmmintrin.h>

//#define USE_AES_NI

class AES{
public:
	enum PaddingMode{
		PADDING_ZERO,
		PADDING_PKCS_5
	};
private:
	static const int MAX_NR=14;// max no of rounds
	static const int FILE_READ_SIZE=65536;

	unsigned int Nr;// number of rounds
#ifdef USE_AES_NI
	__m128i enc_key[MAX_NR+2],dec_key[MAX_NR+2];
	__m128i iv;// initialization vector

	__m128i AES_128_ASSIST(__m128i temp1,__m128i temp2);
	void AES_192_ASSIST(__m128i &temp1,__m128i &temp2,__m128i &temp3);
	void AES_256_ASSIST_1(__m128i &temp1,__m128i &temp2);
	void AES_256_ASSIST_2(__m128i &temp1,__m128i &temp3);
	void AES_128_Key_Expansion(__m128i *key,const unsigned char *user_key);
	void AES_192_Key_Expansion(__m128i *key,const unsigned char *user_key);
	void AES_256_Key_Expansion(__m128i *key,const unsigned char *user_key);
#else
	unsigned char iv[16];// initialization vector
	unsigned char roundKey[16*(MAX_NR+1)];

	inline void ExtMul(unsigned char &x,unsigned char data,int n);
	void SubWord(unsigned char *w);
	void RotWord(unsigned char *w);
	void KeyExpansion(const unsigned char *userKey,int wordKeyLength);

	inline void SubBytes(unsigned char *data);
	inline void ShiftRows(unsigned char *data);
	inline void MixColumns(unsigned char *data);
	inline void InvSubBytes(unsigned char *data);
	inline void InvShiftRows(unsigned char *data);
	inline void InvMixColumns(unsigned char *data);
	inline void AddRoundKey(unsigned char *data,int n);
#endif

	int Padding(char *ret,PaddingMode mode,int val);
	void RemovePadding(FILE *fp_out,const char *buf,PaddingMode mode,int end_point);
public:
	AES(std::string key,unsigned int key_bit_length,const char *init_vec=NULL);
	~AES(){}

#ifdef USE_AES_NI
	__m128i Encrypt(__m128i data);
	__m128i Decrypt(__m128i data);
	__m128i Encrypt_CBC(__m128i data,__m128i &vec);
	__m128i Decrypt_CBC(__m128i data,__m128i &vec);
#else
	void Encrypt(unsigned char *data);
	void Decrypt(unsigned char *data);
	void Encrypt_CBC(unsigned char *data,unsigned char *vec);
	void Decrypt_CBC(unsigned char *data,unsigned char *vec);
#endif

	void Encrypt(std::string in_fname,std::string out_fname,bool cbc,PaddingMode mode);
	void Decrypt(std::string in_fname,std::string out_fname,bool cbc,PaddingMode mode);
};
