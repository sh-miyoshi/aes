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
	char buf[16];
	switch(mode){
	case MODE_ENCRYPT:
		while(feof(fp_in)==0){
			memset(buf,0,sizeof(buf));
			int s=fread(buf,sizeof(char),16,fp_in);
			__m128i data=_mm_load_si128((__m128i *)buf);
			__m128i ret=aes.Encrypt(data);
			_mm_store_si128((__m128i *)buf,data);
			fwrite(buf,sizeof(char),s,fp_out);
		}
		break;
	case MODE_DECRYPT:
		while(feof(fp_in)==0){
			memset(buf,0,sizeof(buf));
			int s=fread(buf,sizeof(char),16,fp_in);
			__m128i data=_mm_load_si128((__m128i *)buf);
			__m128i ret=aes.Decrypt(data);
			_mm_store_si128((__m128i *)buf,data);
			fwrite(buf,sizeof(char),s,fp_out);
		}
		break;
	}
	fclose(fp_out);
	fclose(fp_in);
	return 0;
}
