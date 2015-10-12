#include <iostream>
#include <string.h>
#include "aes.h"
using namespace std;

int main(){
/*	__m128i enc_key[11],dec_key[11];
	AES_Setup(enc_key,dec_key,"test");
	char data[16],ret[16]={0};
	strcpy(data,"0123456789012345");
//	cout<<data<<endl;
	__m128i t=_mm_loadu_si128((__m128i*)data);
	t=AES_Encrypt(t,enc_key);
	t=AES_Decrypt(t,dec_key);
	_mm_storeu_si128((__m128i*)ret,t);
	for(int i=0;i<16;i++)
		cout<<(char)ret[i]<<" ";
	cout<<endl;*/
	
	unsigned char data[16],ret[16]={0},key[16];
	strcpy((char *)data,"0123456789012345");
	strcpy((char *) key,"testtesttesttest");
	for(int i=0;i<16;i++)
		cout<<(char)data[i]<<" ";
	cout<<endl;
	AESContext ctx;
    aes_setup(&ctx, key, 16);
    memset(ctx.iv, 0, sizeof(ctx.iv));
    aes_encrypt_cbc(data, 16, &ctx);
    for(int i=0;i<16;i++)
		cout<<(char)data[i]<<" ";
	cout<<endl;

    aes_setup(&ctx, key, 16);
    memset(ctx.iv, 0, sizeof(ctx.iv));
    aes_decrypt_cbc(data, 16, &ctx);
    for(int i=0;i<16;i++)
		cout<<(char)data[i]<<" ";
	cout<<endl;

}
