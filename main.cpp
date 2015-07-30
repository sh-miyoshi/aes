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
	std::cerr<<"    or -d cipher_file"<<std::endl;
}

int main(int argc,char *argv[]){
	enum Mode{
		MODE_ENCRYPT,
		MODE_DECRYPT
	};
	Mode mode=MODE_ENCRYPT;
	std::string input_fname;
	std::string output_fname;
	if(argc==4){// maybe encryption
		if(strcmp(argv[1],"-e")==0){
			input_fname=argv[2];
			output_fname=argv[3];
			mode=MODE_ENCRYPT;
			goto PROCESS;
		}
	}else if(argc==3){// maybe decryption
		if(strcmp(argv[1],"-d")==0){
			input_fname=argv[2];
			mode=MODE_DECRYPT;
			goto PROCESS;
		}
	}

	// Input error
	PrintHelpMessage();
	return 1;
PROCESS:
	std::string password="test";
	AES aes(AES::TYPE_256,password);

	FILE *fp=fopen(input_fname.c_str(),"rb");
	if(!fp){
		std::cerr<<"cannot open file "<<input_fname<<std::endl;
		return 1;
	}

	unsigned char buf[128];
	FILE *out_fp;
	switch(mode){
	case MODE_ENCRYPT:
		out_fp=fopen(output_fname.c_str(),"wb");
		if(!out_fp){
			std::cerr<<"cannot open file "<<output_fname<<std::endl;
			return 1;
		}

		// data encrypting
		while(feof(fp)){
			memset(buf,0,sizeof(buf));
			fread(buf,sizeof(char),16,fp);
			__m128i data=_mm_set_epi8(
				buf[ 0],buf[ 1],buf[ 2],buf[ 3],
				buf[ 4],buf[ 5],buf[ 6],buf[ 7],
				buf[ 8],buf[ 9],buf[10],buf[11],
				buf[12],buf[13],buf[14],buf[15]
			);
			__m128i ret=aes.Encrypt(data);
			uint8_t *temp=(uint8_t *)&ret;
			fwrite(temp,16,1,fp);
		}

		fclose(out_fp);
		break;
	case MODE_DECRYPT:
		break;
	}
	fclose(fp);
}
