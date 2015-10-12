#include <iostream>
#include <stdlib.h>
#include "aes.h"

AES::AES(std::string key,unsigned int key_bit_length,const char *init_vec){
	unsigned int kl_byte=key_bit_length/8;
	unsigned char uk[32];
	for(int i=0;i<kl_byte;i++)
		uk[i]=key[i%key.size()];
	Nr=6+(kl_byte/4);
	switch(key_bit_length){
	case 128:
		AES_128_Key_Expansion(enc_key,uk);
		break;
	case 192:
		AES_192_Key_Expansion(enc_key,uk);
		break;
	case 256:
		AES_256_Key_Expansion(enc_key,uk);
		break;
	default:
		std::cerr<<key_bit_length<<"-bit AES is not supported in this program\n";
		exit(1);
	}

	dec_key[Nr]=enc_key[0];
	for(int i=1;i<Nr;i++)
		dec_key[Nr-i]=_mm_aesimc_si128(enc_key[i]);
	dec_key[0]=enc_key[Nr];

	if(init_vec==NULL)
		this->iv=_mm_setzero_si128();
	else
		this->iv=_mm_loadu_si128((__m128i *)init_vec);
}

__m128i AES::Encrypt(__m128i data){
	data=_mm_xor_si128(data,enc_key[0]);
	for(int i=1;i<Nr;i++)
		data=_mm_aesenc_si128(data,enc_key[i]);
	return _mm_aesenclast_si128(data,enc_key[Nr]);
}

__m128i AES::Decrypt(__m128i data){
	data=_mm_xor_si128(data,dec_key[0]);
	for(int i=1;i<Nr;i++)
		data=_mm_aesdec_si128(data,dec_key[i]);
	return _mm_aesdeclast_si128(data,dec_key[Nr]);
}

//void AES::Encrypt_CBC(unsigned char *enc,const unsigned char *data,int length){}
//void AES::Decrypt_CBC(unsigned char *dec,const unsigned char *data,int length){}

__m128i AES::AES_128_ASSIST(__m128i temp1,__m128i temp2){
	__m128i temp3;
	temp2=_mm_shuffle_epi32(temp2,0xff);
	temp3=_mm_slli_si128(temp1,0x4);
	temp1=_mm_xor_si128(temp1,temp3);
	temp3=_mm_slli_si128(temp3,0x4);
	temp1=_mm_xor_si128(temp1,temp3);
	temp3=_mm_slli_si128(temp3,0x4);
	temp1=_mm_xor_si128(temp1,temp3);
	temp1=_mm_xor_si128(temp1,temp2);
	return temp1;
}

void AES::AES_192_ASSIST(__m128i &temp1,__m128i &temp2,__m128i &temp3){
    __m128i temp4;
    temp2=_mm_shuffle_epi32(temp2,0x55);
    temp4=_mm_slli_si128(temp1,0x4);
    temp1=_mm_xor_si128(temp1,temp4);
    temp4=_mm_slli_si128(temp4,0x4);
    temp1=_mm_xor_si128(temp1,temp4);
    temp4=_mm_slli_si128(temp4,0x4);
    temp1=_mm_xor_si128(temp1,temp4);
    temp1=_mm_xor_si128(temp1,temp2);
    temp2=_mm_shuffle_epi32(temp1,0xff);
    temp4=_mm_slli_si128(temp3,0x4);
    temp3=_mm_xor_si128(temp3,temp4);
    temp3=_mm_xor_si128(temp3,temp2);
}

void AES::AES_256_ASSIST_1(__m128i &temp1,__m128i &temp2){
	__m128i temp4;
	temp2=_mm_shuffle_epi32(temp2,0xff);
	temp4=_mm_slli_si128(temp1,0x4);
	temp1=_mm_xor_si128(temp1,temp4);
	temp4=_mm_slli_si128(temp4,0x4);
	temp1=_mm_xor_si128(temp1,temp4);
	temp4=_mm_slli_si128(temp4,0x4);
	temp1=_mm_xor_si128(temp1,temp4);
	temp1=_mm_xor_si128(temp1,temp2);
}

void AES::AES_256_ASSIST_2(__m128i &temp1,__m128i &temp3){
	__m128i temp2,temp4;
	temp4=_mm_aeskeygenassist_si128(temp1,0x0);
	temp2=_mm_shuffle_epi32(temp4,0xaa);
	temp4=_mm_slli_si128(temp3,0x4);
	temp3=_mm_xor_si128(temp3,temp4);
	temp4=_mm_slli_si128(temp4,0x4);
	temp3=_mm_xor_si128(temp3,temp4);
	temp4=_mm_slli_si128(temp4,0x4);
	temp3=_mm_xor_si128(temp3,temp4);
	temp3=_mm_xor_si128(temp3,temp2);
}

void AES::AES_128_Key_Expansion(__m128i *key,const unsigned char *user_key){
	__m128i temp1=_mm_loadu_si128((__m128i *)user_key),temp2;
	key[0]=temp1;
	for(int i=1;i<=10;i++){
		switch(i){
		case  1:temp2=_mm_aeskeygenassist_si128(temp1,0x1 );break;
		case  2:temp2=_mm_aeskeygenassist_si128(temp1,0x2 );break;
		case  3:temp2=_mm_aeskeygenassist_si128(temp1,0x4 );break;
		case  4:temp2=_mm_aeskeygenassist_si128(temp1,0x8 );break;
		case  5:temp2=_mm_aeskeygenassist_si128(temp1,0x10);break;
		case  6:temp2=_mm_aeskeygenassist_si128(temp1,0x20);break;
		case  7:temp2=_mm_aeskeygenassist_si128(temp1,0x40);break;
		case  8:temp2=_mm_aeskeygenassist_si128(temp1,0x80);break;
		case  9:temp2=_mm_aeskeygenassist_si128(temp1,0x1b);break;
		case 10:temp2=_mm_aeskeygenassist_si128(temp1,0x36);break;
		}
		temp1=AES_128_ASSIST(temp1,temp2);
		key[i]=temp1;
	}
}

void AES::AES_192_Key_Expansion(__m128i *key,const unsigned char *user_key){
	__m128i temp1,temp2,temp3;
	temp1=_mm_loadu_si128((__m128i*)user_key);
	temp3=_mm_loadu_si128((__m128i*)(user_key+16));
	for(int i=0;i<12;i+=3){
		key[i]=temp1;
		key[i+1]=temp3;
		switch(i){
		case 0:temp2=_mm_aeskeygenassist_si128(temp3,0x1 );break;
		case 3:temp2=_mm_aeskeygenassist_si128(temp3,0x4 );break;
		case 6:temp2=_mm_aeskeygenassist_si128(temp3,0x10);break;
		case 9:temp2=_mm_aeskeygenassist_si128(temp3,0x40);break;
		}
		AES_192_ASSIST(temp1,temp2,temp3);
		key[i+1]=(__m128i)_mm_shuffle_pd((__m128d)key[i+1],(__m128d)temp1,0);
		key[i+2]=(__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
		switch(i){
		case 0:temp2=_mm_aeskeygenassist_si128(temp3,0x2 );break;
		case 3:temp2=_mm_aeskeygenassist_si128(temp3,0x8 );break;
		case 6:temp2=_mm_aeskeygenassist_si128(temp3,0x20);break;
		case 9:temp2=_mm_aeskeygenassist_si128(temp3,0x80);break;
		}
		AES_192_ASSIST(temp1,temp2,temp3);
	}
	key[12]=temp1;
	key[13]=temp3;
}

void AES::AES_256_Key_Expansion(__m128i *key,const unsigned char *user_key){
	__m128i temp1,temp2,temp3;
	temp1=_mm_loadu_si128((__m128i*)user_key);
	temp3=_mm_loadu_si128((__m128i*)(user_key+16));
	key[0]=temp1;
	key[1]=temp3;
	for(int i=2;i<=12;i+=2){
		switch(i){
		case  2:temp2=_mm_aeskeygenassist_si128(temp3,0x01 );break;
		case  4:temp2=_mm_aeskeygenassist_si128(temp3,0x02 );break;
		case  6:temp2=_mm_aeskeygenassist_si128(temp3,0x04 );break;
		case  8:temp2=_mm_aeskeygenassist_si128(temp3,0x08 );break;
		case 10:temp2=_mm_aeskeygenassist_si128(temp3,0x010);break;
		case 12:temp2=_mm_aeskeygenassist_si128(temp3,0x020);break;
		}
		AES_256_ASSIST_1(temp1,temp2);
		key[i]=temp1;
		AES_256_ASSIST_2(temp1,temp3);
		key[i+1]=temp3;
	}
	temp2=_mm_aeskeygenassist_si128(temp3,0x40);
	AES_256_ASSIST_1(temp1,temp2);
	key[14]=temp1;
}
