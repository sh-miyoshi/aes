#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include "aes.h"

#ifndef USE_AES_NI
static const unsigned char SBOX[256]={
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const unsigned char INV_SBOX[256]={
	0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
	0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
	0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
	0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
	0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
	0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
	0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
	0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
	0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
	0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
	0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
	0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
	0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
	0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
	0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
	0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};
#endif

AES::AES(std::string key,unsigned int key_bit_length,const char *init_vec){
	unsigned int kl_byte=key_bit_length/8;
	unsigned char uk[32];
	for(int i=0;i<kl_byte;i++)
		uk[i]=key[i%key.size()];
	Nr=6+(kl_byte/4);

#ifdef USE_AES_NI
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
#else
	for(int i=0;i<16;i++){
		if(init_vec==NULL)
			iv[i]=0;
		else
			iv[i]=init_vec[i];
	}

	KeyExpansion(uk,key_bit_length/32);
#endif
}

#ifdef USE_AES_NI
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

__m128i AES::Encrypt_CBC(__m128i data,__m128i &vec){
	__m128i ret=_mm_xor_si128(data,vec);
	ret=Encrypt(ret);
	vec=_mm_xor_si128(data,ret);
	return ret;
}

__m128i AES::Decrypt_CBC(__m128i data,__m128i &vec){
	__m128i ret=Decrypt(data);
	ret=_mm_xor_si128(ret,vec);
	vec=_mm_xor_si128(data,ret);
	return ret;
}
#else
void AES::Encrypt(unsigned char *data){
	AddRoundKey(data,0);
	for(int i=1;i<Nr;i++){
		SubBytes(data);
		ShiftRows(data);
		MixColumns(data);
		AddRoundKey(data,i);
	}

	SubBytes(data);
	ShiftRows(data);
	AddRoundKey(data,Nr);
}

void AES::Decrypt(unsigned char *data){
	AddRoundKey(data,Nr);
	for(int i=Nr-1;i>0;i--){
		InvShiftRows(data);
		InvSubBytes(data);
		AddRoundKey(data,i);
		InvMixColumns(data);
	}

	InvShiftRows(data);
	InvSubBytes(data);
	AddRoundKey(data,0);
}

void AES::Encrypt_CBC(unsigned char *data,unsigned char *vec){
	unsigned char temp[16];
	for(int i=0;i<16;i++){
		temp[i]=data[i];
		data[i]|=vec[i];
	}
	Encrypt(data);
	for(int i=0;i<16;i++)
		vec[i]=data[i]^temp[i];
}

void AES::Decrypt_CBC(unsigned char *data,unsigned char *vec){
	unsigned char temp[16];
	for(int i=0;i<16;i++)
		temp[i]=data[i];
	Decrypt(data);
	for(int i=0;i<16;i++){
		data[i]|=vec[i];
		vec[i]=data[i]^temp[i];
	}
}

#endif

void AES::Encrypt(std::string in_fname,std::string out_fname,bool cbc,AES::PaddingMode mode){
	FILE *fp_in=fopen(in_fname.c_str(),"rb");
	FILE *fp_out=fopen(out_fname.c_str(),"wb");
	if(!fp_in){
		std::cerr<<"ERROR: cannot open file: "<<in_fname<<"\n";
		exit(1);
	}
	if(!fp_out){
		std::cerr<<"ERROR: cannot open file: "<<out_fname<<"\n";
		exit(1);
	}
	char buf[FILE_READ_SIZE],ret[FILE_READ_SIZE];
	bool is_padding=false;
#ifdef USE_AES_NI
	__m128i cbc_vec=iv;
#else
	unsigned char cbc_vec[16];
	for(int i=0;i<16;i++)
		cbc_vec[i]=iv[i];
#endif
	while(1){
		memset(buf,0,sizeof(buf));
		int size=fread(buf,sizeof(char),FILE_READ_SIZE,fp_in);
		if(size==0){
			if(!is_padding){// encrypt 128bit or 0bit
				int n=Padding(buf,mode,16);
				if(n>0){
#ifdef USE_AES_NI
					__m128i data;
					data=_mm_loadu_si128((__m128i *)buf);
					if(cbc)
						data=Encrypt_CBC(data,cbc_vec);
					else
						data=Encrypt(data);
					_mm_storeu_si128((__m128i *)(buf),data);
#else
					if(cbc)
						Encrypt_CBC((unsigned char *)buf,cbc_vec);
					else
						Encrypt((unsigned char *)buf);
#endif
					fwrite(buf,sizeof(char),16,fp_out);
				}
			}
			break;
		}else if(size<FILE_READ_SIZE){
			is_padding=true;
			size+=Padding(buf+size,mode,16-(size&15));
		}
		int max=(int)(size/16.0+0.95);// size>=1なら桁上げして切り捨て
		for(int i=0;i<max;i++){
			char t[16]={0};
			for(int j=0;j<16;j++)
				t[j]=buf[i*16+j];
#ifdef USE_AES_NI
			__m128i data=_mm_loadu_si128((__m128i *)t);
			if(cbc)
				data=Encrypt_CBC(data,cbc_vec);
			else
				data=Encrypt(data);
			_mm_storeu_si128((__m128i *)(ret+(i*16)),data);
#else
			if(cbc)
				Encrypt_CBC((unsigned char *)t,cbc_vec);
			else
				Encrypt((unsigned char *)t);
			for(int j=0;j<16;j++)
				ret[i*16+j]=t[j];
#endif
		}
		fwrite(ret,sizeof(char),max*16,fp_out);
	}
	fclose(fp_in);
	fclose(fp_out);
}

void AES::Decrypt(std::string in_fname,std::string out_fname,bool cbc,AES::PaddingMode mode){
	FILE *fp_in=fopen(in_fname.c_str(),"rb");
	FILE *fp_out=fopen(out_fname.c_str(),"wb");
	if(!fp_in){
		std::cerr<<"ERROR: cannot open file: "<<in_fname<<"\n";
		exit(1);
	}
	if(!fp_out){
		std::cerr<<"ERROR: cannot open file: "<<out_fname<<"\n";
		exit(1);
	}
	char buf[2][FILE_READ_SIZE],dec[FILE_READ_SIZE],ret[FILE_READ_SIZE];
	memset(buf[0],0,sizeof(buf[0]));
	int size=fread(buf[0],sizeof(char),FILE_READ_SIZE,fp_in);
	if(size==0)
		return;
#ifdef USE_AES_NI
	__m128i cbc_vec=iv;
#else
	unsigned char cbc_vec[16];
	for(int i=0;i<16;i++)
		cbc_vec[i]=iv[i];
#endif
	while(1){
		memcpy(buf[1],buf[0],size);
		for(int i=0;i<size/16;i++){
			char t[16]={0};
			for(int j=0;j<16;j++)
				t[j]=buf[1][i*16+j];
#ifdef USE_AES_NI
			__m128i data=_mm_loadu_si128((__m128i *)t);
			if(cbc)
				data=Decrypt_CBC(data,cbc_vec);
			else
				data=Decrypt(data);
			_mm_storeu_si128((__m128i *)(dec+(i*16)),data);
#else
			if(cbc)
				Decrypt_CBC((unsigned char *)t,cbc_vec);
			else
				Decrypt((unsigned char *)t);
			for(int j=0;j<16;j++)
				dec[i*16+j]=t[j];
#endif
		}
		memcpy(ret,dec,size);
		if(size<FILE_READ_SIZE){
			fwrite(ret,sizeof(char),size-16,fp_out);
			RemovePadding(fp_out,ret,mode,size);
			break;
		}else{
			memcpy(buf[1],buf[0],FILE_READ_SIZE);
			memset(buf[0],0,sizeof(buf[0]));
			int s2=fread(buf[0],sizeof(char),FILE_READ_SIZE,fp_in);
			if(s2==0){
				fwrite(ret,sizeof(char),FILE_READ_SIZE-16,fp_out);
				// buf[1]最後のバイト列はpaddingの可能性
				RemovePadding(fp_out,ret,mode,FILE_READ_SIZE);
				break;
			}
			size=s2;
			fwrite(ret,sizeof(char),FILE_READ_SIZE,fp_out);
		}
	}
	fclose(fp_in);
	fclose(fp_out);
}

#ifdef USE_AES_NI
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
#else
void AES::SubBytes(unsigned char *data){
	for(int i=0;i<16;i++)
		data[i]=SBOX[data[i]];
}

void AES::ShiftRows(unsigned char *data){
	unsigned char temp=data[4];

	// line 1
	data[4]=data[5];
	data[5]=data[6];
	data[6]=data[7];
	data[7]=temp;

	// line 2
	temp=data[8];
	data[8]=data[10];
	data[10]=temp;
	temp=data[9];
	data[9]=data[11];
	data[11]=temp;

	// line 3
	temp=data[15];
	data[15]=data[14];
	data[14]=data[13];
	data[13]=data[12];
	data[12]=temp;
}

void AES::MixColumns(unsigned char *data){
	// 要改善
	unsigned char buf[8];
	for(int x=0;x<4;x++){
		for(int y=0;y<4;y++)
			buf[y]=data[(y<<2)+x];
		ExtMul(buf[4],buf[0],2);
		ExtMul(buf[5],buf[1],3);
		ExtMul(buf[6],buf[2],1);
		ExtMul(buf[7],buf[3],1);
		data[x+0]=buf[4]^buf[5]^buf[6]^buf[7];
		ExtMul(buf[4],buf[0],1);
		ExtMul(buf[5],buf[1],2);
		ExtMul(buf[6],buf[2],3);
		ExtMul(buf[7],buf[3],1);
		data[x+4]=buf[4]^buf[5]^buf[6]^buf[7];
		ExtMul(buf[4],buf[0],1);
		ExtMul(buf[5],buf[1],1);
		ExtMul(buf[6],buf[2],2);
		ExtMul(buf[7],buf[3],3);
		data[x+8]=buf[4]^buf[5]^buf[6]^buf[7];
		ExtMul(buf[4],buf[0],3);
		ExtMul(buf[5],buf[1],1);
		ExtMul(buf[6],buf[2],1);
		ExtMul(buf[7],buf[3],2);
		data[x+12]=buf[4]^buf[5]^buf[6]^buf[7];
	}
}

void AES::InvSubBytes(unsigned char *data){
	for(int i=0;i<16;i++)
		data[i]=INV_SBOX[data[i]];
}

void AES::InvShiftRows(unsigned char *data){
	// 要改善
	unsigned char buf[16];
	memcpy(buf,data,sizeof(buf));
	for(int i=1;i<4;i++){
		for(int j=0;j<4;j++)
			data[i*4+(j+i)%4]=buf[i*4+j];
	}
}

void AES::InvMixColumns(unsigned char *data){
	// 要改善
	unsigned char x;
	unsigned char buf[8];
	for(int x=0;x<4;x++){
		for(int y=0;y<4;y++)
			buf[y]=data[y*4+x];
		ExtMul(buf[4],buf[0],14);
		ExtMul(buf[5],buf[1],11);
		ExtMul(buf[6],buf[2],13);
		ExtMul(buf[7],buf[3],9);
		data[x+0]=buf[4]^buf[5]^buf[6]^buf[7];
		ExtMul(buf[4],buf[0],9);
		ExtMul(buf[5],buf[1],14);
		ExtMul(buf[6],buf[2],11);
		ExtMul(buf[7],buf[3],13);
		data[x+4]=buf[4]^buf[5]^buf[6]^buf[7];
		ExtMul(buf[4],buf[0],13);
		ExtMul(buf[5],buf[1],9);
		ExtMul(buf[6],buf[2],14);
		ExtMul(buf[7],buf[3],11);
		data[x+8]=buf[4]^buf[5]^buf[6]^buf[7];
		ExtMul(buf[4],buf[0],11);
		ExtMul(buf[5],buf[1],13);
		ExtMul(buf[6],buf[2],9);
		ExtMul(buf[7],buf[3],14);
		data[x+12]=buf[4]^buf[5]^buf[6]^buf[7];
	}
}

void AES::AddRoundKey(unsigned char *data,int n){
	for(int i=0;i<16;i++)
		data[i]^=roundKey[(n<<4)+i];
}

void AES::ExtMul(unsigned char &x,unsigned char data,int n){
	x=0;
	if(n&8)
		x=data;
	bool flag=x&0x80;
	x<<=1;
	if(flag)
		x^=0x1b;
	if(n&4)
		x^=data;
	flag=x&0x80;
	x<<=1;
	if(flag)
		x^=0x1b;
	if(n&2)
		x^=data;
	flag=x&0x80;
	x<<=1;
	if(flag)
		x^=0x1b;
	if(n&1)
		x^=data;
}

void AES::SubWord(unsigned char *w){
	for(int i=0;i<4;i++)
		w[i]=SBOX[16*((w[i]&0xf0)>>4)+(w[i]&0x0f)];
}

void AES::RotWord(unsigned char *w){
	unsigned char temp=w[0];
	for(int i=0;i<3;i++)
		w[i]=w[i+1];
	w[3]=temp;
}

void AES::KeyExpansion(const unsigned char *userKey,int wordKeyLength){
	static const unsigned char Rcon[10]={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

	unsigned char *w=roundKey,len=4*(Nr+1),buf[4];
	memcpy(w,userKey,wordKeyLength*4);

	for(int i=wordKeyLength;i<len;i++){
		buf[0] = w[4*(i-1)+0];
		buf[1] = w[4*(i-1)+1];
		buf[2] = w[4*(i-1)+2];
		buf[3] = w[4*(i-1)+3];

		if(i%wordKeyLength==0){
			RotWord(buf);
			SubWord(buf);
			buf[0]^=Rcon[(i/wordKeyLength)-1];
		}else if(wordKeyLength>6&&i%wordKeyLength==4)
			SubWord(buf);

		w[4*i+0] = w[4*(i-wordKeyLength)+0]^buf[0];
		w[4*i+1] = w[4*(i-wordKeyLength)+1]^buf[1];
		w[4*i+2] = w[4*(i-wordKeyLength)+2]^buf[2];
		w[4*i+3] = w[4*(i-wordKeyLength)+3]^buf[3];
	}
}
#endif

int AES::Padding(char *ret,AES::PaddingMode mode,int val){
	switch(mode){
	case PADDING_ZERO:
		return 0;
	case PADDING_PKCS_5:
		for(int i=0;i<val;i++)
			ret[i]=val;
		return val;
	}
	return 0;
}

void AES::RemovePadding(FILE *fp_out,const char *buf,PaddingMode mode,int end_point){
	switch(mode){
	case PADDING_ZERO:
		for(int i=end_point-16;i<end_point;i++){
			if(buf[i]==0)
				return;
			char c=buf[i];
			fwrite(&c,sizeof(char),1,fp_out);
		}
		break;
	case PADDING_PKCS_5:
		for(int i=0;i<(16-(int)buf[end_point-1]);i++){
			char c=buf[end_point-16+i];
			fwrite(&c,sizeof(char),1,fp_out);
		}
		break;
	}
}
