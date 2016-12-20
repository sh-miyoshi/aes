#ifndef _WINDOWS
#if defined(_WIN64) || defined(_WIN32) || defined(__MINGW32__) || defined(__MINGW64__)
#define _WINDOWS
#endif
#endif

#define TIME_MEASUREMENT

#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "aes.h"
#include "option.h"

#ifdef _WINDOWS
#include <conio.h>
#else
#include <unistd.h>
#endif

using namespace std;

enum Mode{
	MODE_NON,
	MODE_ENCRYPT,
	MODE_DECRYPT
};

void InputPassword(std::string &ret){
#ifdef _WINDOWS
	char c;
	while((c=getch())!='\n'&&c!='\r'){
		if(c=='\b'){// BackSpace
			if(!ret.empty()){
				printf("\b \b");
				ret.erase(ret.size()-1);
			}
		}else if(c<0x20||c>0x7e){// 2byte character in Shift-JIS
			getch();
		}else if(c!='\t'&&c!=0x1b){// Tab,Esc?
			putchar('*');
			ret+=c;
		}
	}
	putchar('\n');
#else
	ret=getpass("Password: ");
#endif
}

int main(int argc,char *argv[]){
	Option opt;
	opt.AddHelpMessage("Usage: aes.exe (--enc or --dec) [options] input_file output_file");
	opt.AddDefine("--cbc","","","if you want to encrypt(or decrypt) with cbc mode");
	opt.AddDefine("--pad-zero","--pad-pkcs5","","select padding type(zero or PKCS#5, default is PKCS#5)");
	opt.AddDefine("-l","--keylen","\"key_length\"","key bit length(128,192,256)");
	opt.AddDefine("-p","--password","\"password\"","set password");
	opt.AddDefine("-?","--help","","show this help message");
	
	if(!opt.SetArguments(argc,argv)){
		opt.ShowHelpMessage();
		return 1;
	}
	std::vector<std::string> opt_non=opt.GetOptionNon();
	bool cbc=false;
	Mode mode=MODE_NON;
	AES::PaddingMode padding_mode=AES::PADDING_PKCS_5;
	for(int i=0;i<opt_non.size();i++){
		if(opt_non[i]=="--help"||opt_non[i]=="-?"){
			opt.ShowHelpMessage();
			return 0;
		}else if(opt_non[i]=="--cbc")
			cbc=true;
		else if(opt_non[i]=="--enc"){
			if(mode==MODE_NON)
				mode=MODE_ENCRYPT;
			else{
				cerr<<"Please input --enc or --dec"<<endl;
				exit(1);
			}
		}else if(opt_non[i]=="--dec"){
			if(mode==MODE_NON)
				mode=MODE_DECRYPT;
			else{
				cerr<<"Please input --enc or --dec";
				exit(1);
			}
		}else if(opt_non[i]=="--pad-zero")
			padding_mode=AES::PADDING_ZERO;
		else if(opt_non[i]=="--pad-pkcs5")
			padding_mode=AES::PADDING_PKCS_5;
		else{
			opt.ShowHelpMessage();
			return 1;
		}
	}
	if(mode==MODE_NON){
		opt.ShowHelpMessage();
		return 1;
	}

	int key_length=128;
	std::string password;
	std::map<std::string,std::string> opt_val=opt.GetOptionValue();
	for(map<string,string>::iterator it=opt_val.begin();it!=opt_val.end();it++){
		if(it->first=="-l"||it->first=="--keylen")
			key_length=atoi(it->second.c_str());
		else if(it->first=="-p"||it->first=="--password")
			password=it->second;
	}
	std::vector<std::string> input=opt.GetInput();
	if(input.size()!=2){
		opt.ShowHelpMessage();
		return 1;
	}

	if(password.empty()){
		cout<<"Please Input Password"<<endl;
		InputPassword(password);
	}

	if(password.empty()){
		cout<<"This system is not allow [encryption|decryption] with empty password."<<endl;
		return 0;
	}

#ifdef TIME_MEASUREMENT
	clock_t start_time=clock();
#endif
	AES aes(password,key_length);
	switch(mode){
	case MODE_ENCRYPT:
		aes.Encrypt(input[0],input[1],cbc,padding_mode);
		break;
	case MODE_DECRYPT:
		aes.Decrypt(input[0],input[1],cbc,padding_mode);
		break;
	}
#ifdef TIME_MEASUREMENT
	clock_t end_time=clock();
	printf("%.2f[sec]\n",(double)(end_time-start_time)/CLOCKS_PER_SEC);
#endif
	return 0;
}
