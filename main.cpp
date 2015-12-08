#include <iostream>
#include <string.h>
#include <stdlib.h>
#include "aes.h"
#include "option.h"
using namespace std;

void ExitArgvError(){
	// Show help message
	cerr<<"Usage: aes.exe [options] input_file output_file"<<endl;
	cerr<<"  --enc or --dec"<<endl;
	cerr<<"  --cbc [if you want to encrypt(or decrypt) with cbc mode]"<<endl;
	cerr<<"  -l \"key_length\" [key bit length(128,192,256)]"<<endl;
	cerr<<"  -p \"password\""<<endl;
	exit(1);
}

enum Mode{
	MODE_NON,
	MODE_ENCRYPT,
	MODE_DECRYPT
};

int main(int argc,char *argv[]){
	Option opt;
	if(!opt.Set(argc,argv))
		ExitArgvError();
	std::vector<std::string> opt_non=opt.GetOptionNon();
	bool cbc=false;
	Mode mode=MODE_NON;
	for(int i=0;i<opt_non.size();i++){
		if(opt_non=="--cbc")
			cbc=true;
		else if(opt_non=="--enc"){
			if(mode==MODE_NON)
				mode=MODE_ENCRYPT;
			else
				ExitArgvError();
		}else if(opt_non=="--dec"){
			if(mode==MODE_NON)
				mode=MODE_DECRYPT;
			else
				ExitArgvError();
		}else
			ExitArgvError();
	}
	if(mode==MODE_NON)
		ExitArgvError();

	int key_length=128;
	std::string password;
	std::map<std::string,std::string> opt_val=opt.GetOptionValue();
	for(map<string,string>::iterator it=opt_val.begin();it!=opt_val.end();it++){
		if(it->first=="-l")
			key_length=atoi(it->second.c_str());
		else if(it->first=="-p")
			password=it->second;
	}
	std::vector<std::string> input=opt.GetInput();

	

	AES aes("1239658740123965874045924815",128);
	aes.Encrypt("test_input.cpp","temp.enc",false,AES::PADDING_ZERO);
	aes.Decrypt("temp.enc","ret.cpp",false,AES::PADDING_ZERO);
	return 0;
}
