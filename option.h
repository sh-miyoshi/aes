#pragma once

#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <iostream>

// This class deal with command line argument
class Option{
	std::map<std::string,std::string> def_non;
	std::map<std::string,std::string> def_val;
	std::string helpMsg;

	std::vector<std::string> opt_non;
	std::map<std::string,std::string> opt_val;
	std::vector<std::string> input;
public:
	Option(){}
	~Option(){}

	void AddHelpMessage(std::string helpMsg){
		this->helpMsg+=helpMsg+"\n";
	}

	bool AddDefine(std::string key,std::string alias,std::string val,std::string msg){
		if(key.empty())
			return false;
		if(!val.empty()){// the option requires argument
			def_val.insert(std::map<std::string,std::string>::value_type(key,msg));
			if(!alias.empty()){
				this->helpMsg+="  "+key+" or "+alias+" "+val+" ["+msg+"]\n";
				return def_val.insert(std::map<std::string,std::string>::value_type(alias,msg)).second;
			}else
				this->helpMsg+="  "+key+" "+val+" ["+msg+"]\n";
		}else{
			def_non.insert(std::map<std::string,std::string>::value_type(key,msg));
			if(!alias.empty()){
				this->helpMsg+="  "+key+" or "+alias+" ["+msg+"]\n";
				return def_non.insert(std::map<std::string,std::string>::value_type(alias,msg)).second;
			}else
				this->helpMsg+="  "+key+" ["+msg+"]\n";
		}
		return true;
	}

	bool SetArguments(int argc,char *argv[]){
		for(int i=1;i<argc;i++){
			std::string val=argv[i];
			if(def_val.count(val)!=0){
				if(i==argc-1)
					return false;
				opt_val.insert(std::map<std::string,std::string>::value_type(val,argv[i+1]));
				i++;
			}else{
				if(def_non.count(val)!=0)
					opt_non.push_back(val);
				else if(val[0]!='-')
					input.push_back(val);
				else
					return false;
			}
		}
		return true;
	}

	void ShowHelpMessage(){
		std::cerr<<helpMsg<<std::endl;
	}

	std::vector<std::string> GetOptionNon()const{return opt_non;}
	std::map<std::string,std::string> GetOptionValue()const{return opt_val;}
	std::vector<std::string> GetInput()const{return input;}
};
