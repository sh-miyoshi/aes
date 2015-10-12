#include <iostream>
#include <string.h>
#include "aes.h"
using namespace std;

int main(){
	char data[16],ret[16];
	strcpy(data,"0123456789012345");
	for(int i=0;i<16;i++)
		cout<<data[i]<<" ";
	cout<<endl;
	AES aes("1239658740123965874045924815",256);
	__m128i t=_mm_loadu_si128((__m128i *)data);
	t=aes.Encrypt(t);
	t=aes.Decrypt(t);
	_mm_storeu_si128((__m128i *)ret,t);
	for(int i=0;i<16;i++)
		cout<<ret[i]<<" ";
	cout<<endl;
}
