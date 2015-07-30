#include <iostream>
#include <string>
#include <conio.h>
#include <stdio.h>
//#include <fstream>
#include <string.h>
#include "aes.h"
using namespace std;

void InputPassword(std::string &ret){
	char c;
	while((c=getch())!='\n'&&c!='\r'){
		if(c=='\b'){// BackSpace
			if(!ret.empty()){
				printf("\b \b");
				ret.erase(ret.size()-1);
			}
		}else if(c<0x20||c>0x7e){// êßå‰ï∂éö,Shift-JIS
			getch();
		}else if(c!='\t'&&c!=0x1b){// Tab,Escà»äOÇ»ÇÁ
			putchar('*');
			ret+=c;
		}
	}
	putchar('\n');
}

void PrintHelpMessage(){
	std::cerr<<"Usage: -e plain_text cipher_text"<<std::endl;
	std::cerr<<"    or -d cipher_text"<<std::endl;
}

int main(int argc,char *argv[]){
	enum Mode{
		MODE_ENCRYPT,
		MODE_DECRYPT
	};
	Mode mode=MODE_ENCRYPT;
	std::string input_fname;
	std::string output_fname;
	if(argc==4){// à√çÜâªÇÃâ¬î\ê´Ç†ÇË
		if(strcmp(argv[1],"-e")==0){
			input_fname=argv[2];
			output_fname=argv[3];
			mode=MODE_ENCRYPT;
			goto PROCESS;
		}
	}else if(argc==3){// ïúçÜÇÃâ¬î\ê´Ç†ÇË
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
	std::string password;
	cout<<"Please Input Password"<<endl;
	InputPassword(password);
	AES aes(AES::TYPE_256,password);

	FILE *fp;
	switch(mode){
	case MODE_ENCRYPT:
		fp=fopen(input_fname.c_str(),"r");
		if(fp){
			std::string data;
			char c;
			while((c=fgetc(fp))!=EOF)
				data+=c;
			fclose(fp);

			string cipher=aes.Encrypt(data);
			fp=fopen(output_fname.c_str(),"wb");
			if(fp){
				fwrite(cipher.c_str(),cipher.size(),1,fp);
				fclose(fp);
			}else{
				std::cerr<<"cannot open file: "<<output_fname<<std::endl;
				return 1;
			}
		}else{
			std::cerr<<"cannot open file: "<<input_fname<<std::endl;
			return 1;
		}
		break;
	case MODE_DECRYPT:
		fp=fopen(input_fname.c_str(),"rb");
		if(fp){
			char buf[256];
			int size=fread(buf,sizeof(char),256,fp);
			fclose(fp);
			std::string data;
			for(int i=0;i<size;i++)
				data+=buf[i];

			string decrypted=aes.Decrypt(data);
			cout<<decrypted<<endl;
		}else{
			std::cerr<<"cannot open file: "<<input_fname<<std::endl;
			return 1;
		}
		break;
	}
}
