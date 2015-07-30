#include "aes.h"

//---------------------------------------------------------------
// Global functions
//---------------------------------------------------------------
AES::AES(Type type,std::string key){
	switch(type){
	case TYPE_128:
		ROUND_NUM=10;
		break;
	case TYPE_192:
		ROUND_NUM=12;
		break;
	case TYPE_256:
		ROUND_NUM=14;
		break;
	}
	bkey=GetBinaryKey(key);
}

AES::~AES(){
}

__m128i AES::Encrypt(__m128i data){
	for(int i=0;i<ROUND_NUM-1;i++)
		data=_mm_aesenc_si128(data,bkey);
	return _mm_aesenclast_si128(data,bkey);
}

__m128i AES::Decrypt(__m128i data){
	for(int i=0;i<ROUND_NUM-1;i++)
		data=_mm_aesdec_si128(data,bkey);
	return _mm_aesdeclast_si128(data,bkey);
}

//---------------------------------------------------------------
// Local functions
//---------------------------------------------------------------
__m128i AES::GetBinaryKey(std::string key){
	for(int i=0;key.size()<16;i++)
		key.push_back(key[i]);
	return _mm_set_epi8(
		key[ 0],key[ 1],key[ 2],key[ 3],
		key[ 4],key[ 5],key[ 6],key[ 7],
		key[ 8],key[ 9],key[10],key[11],
		key[12],key[13],key[14],key[15]
	);
}
