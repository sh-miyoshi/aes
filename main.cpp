#include <iostream>
#include <string>
#include <conio.h>
#include <stdio.h>
#include <stdint.h>
//#include <fstream>
#include <string.h>
#include "aes.h"
using namespace std;

void PrintHelpMessage(){
	std::cerr<<"Usage: -e plain_file cipher_file"<<std::endl;
	std::cerr<<"    or -d cipher_file plain_file"<<std::endl;
}

int main(int argc,char *argv[]){
	// set encryption or decription
	enum Mode{
		MODE_ENCRYPT,
		MODE_DECRYPT
	};
	Mode mode=MODE_ENCRYPT;
	std::string input_fname;
	std::string output_fname;
	if(argc==4){
		if(strcmp(argv[1],"-e")==0)
			mode=MODE_ENCRYPT;
		else if(strcmp(argv[1],"-d")==0)
			mode=MODE_DECRYPT;
		else
			goto INPUT_ERROR;
		input_fname=argv[2];
		output_fname=argv[3];
	}else{
INPUT_ERROR:
		// Input error
		PrintHelpMessage();
		return 1;
	}

	// set password
	std::string password="test";
	AES aes(AES::TYPE_256,password);

	// file configuration
	FILE *fp_in=fopen(input_fname.c_str(),"rb");
	if(!fp_in){
		std::cerr<<"cannot open file "<<input_fname<<std::endl;
		return 1;
	}
	FILE *fp_out=fopen(output_fname.c_str(),"wb");
	if(!fp_out){
		std::cerr<<"cannot open file "<<output_fname<<std::endl;
		return 1;
	}

	// main routine
	unsigned char buf[16];
	switch(mode){
	case MODE_ENCRYPT:
		while(feof(fp_in)==0){
			memset(buf,0,sizeof(buf));
			fread(buf,sizeof(char),16,fp_in);
			__m128i data=_mm_set_epi8(
				buf[ 0],buf[ 1],buf[ 2],buf[ 3],
				buf[ 4],buf[ 5],buf[ 6],buf[ 7],
				buf[ 8],buf[ 9],buf[10],buf[11],
				buf[12],buf[13],buf[14],buf[15]
			);
			__m128i ret=aes.Encrypt(data);
			uint8_t *temp=(uint8_t *)&ret;
			fwrite(temp,sizeof(uint8_t),16,fp_out);
		}
		break;
	case MODE_DECRYPT:
		while(feof(fp_in)==0){
			memset(buf,0,sizeof(buf));
			fread(buf,sizeof(char),16,fp_in);
			__m128i data=_mm_set_epi8(
				buf[ 0],buf[ 1],buf[ 2],buf[ 3],
				buf[ 4],buf[ 5],buf[ 6],buf[ 7],
				buf[ 8],buf[ 9],buf[10],buf[11],
				buf[12],buf[13],buf[14],buf[15]
			);
			__m128i ret=aes.Decrypt(data);
			uint8_t *temp=(uint8_t *)&ret;
			fwrite(temp,sizeof(uint8_t),16,fp_out);
		}
		break;
	}
	fclose(fp_out);
	fclose(fp_in);
	return 0;
}
