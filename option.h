#pragma once

#include <string>
#include <map>
#include <vector>

// This class deal with command line argument
class Option{
	std::vector<std::string> opt_non;
	std::map<std::string,std::string> opt_val;
	std::vector<std::string> input;
public:
	Option(){}
	~Option(){}

	bool Set(int argc,char *argv[]){
		for(int i=1;i<argc;i++){
			if(argv[i][0]=='-'){
				if(argv[i][1]=='-')
					opt_non.push_back(argv[i]);
				else{
					if(i==argc-1)
						return false;
					if(argv[i+1][0]=='-')
						return false;
					opt_val.insert(std::map<std::string,std::string>::value_type(argv[i],argv[i+1]));
					i++;
				}
			}else
				input.push_back(argv[i]);
		}
		return true;
	}

	std::vector<std::string> GetOptionNon()const{return opt_non;}
	std::map<std::string,std::string> GetOptionValue()const{return opt_val;}
	std::vector<std::string> GetInput()const{return input;}
};
