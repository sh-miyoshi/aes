#include <iostream>
#include <string.h>
#include "aes.h"
using namespace std;

int main(){
	AES aes("1239658740123965874045924815",128);
	aes.Encrypt("test_input.cpp","temp.enc",false);
	aes.Decrypt("temp.enc","ret.cpp",false);
}
