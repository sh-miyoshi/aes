#define XBYAK_NO_OP_NAMES
#include <iostream>
//#include <windows.h>
#include "xbyak/xbyak.h"
using namespace std;
typedef unsigned long long ull;
#define RDTSC(X) asm volatile ("rdtsc" : "=A" (X))

double get_usage_sec(){
	LARGE_INTEGER time, freq;
	QueryPerformanceCounter(&time);
	QueryPerformanceFrequency(&freq);
	return static_cast<double>(time.QuadPart) / freq.QuadPart;
}

struct AsmFpAddX:public Xbyak::CodeGenerator{
	// void func(&x_h[rcx],&x_l[rdx],y_h[r8],y_l[r9])
	// mov(8),add(1),adc(1),sub(1),sbb(1),cmp(2),jmp(3)
	AsmFpAddX(ull mod_h,ull mod_l){
		mov(rax,ptr[rcx]);
		mov(r10,ptr[rdx]);
		mov(r11,mod_h);
		add(r10,r9);
		adc(rax,r8);
		cmp(rax,r11);
		ja("mod");
		jb("exit");
		mov(r11,mod_l);
		cmp(r10,r11);
		jb("exit");
	L("mod");
		mov(r8,mod_l);
		mov(r11,mod_h);
		sub(r10,r8);
		sbb(rax,r11);
	L("exit");
		mov(ptr[rcx],rax);
		mov(ptr[rdx],r10);
		ret();
	}
};

struct AsmMDMul:public Xbyak::CodeGenerator{
	// void func(&x_h[rcx],&x_l[rdx],y_h[r8],y_l[r9])
	// COST: push(4),pop(4),mov(25),xor(2),mul(10),add(8),adc(10),sub(1),sbb(1),cmp(2),jmp(3)
	AsmMDMul(ull mod_h,ull mod_l,ull w_dash){
		push(r12);
		push(r13);
		push(r14);
		push(r15);
		mov(rax,ptr[rdx]);// rax=x[0]
		mov(r10,rdx);// r10=&x[0]
		mov(r11,rax);
		xor_(r15,r15);
		mul(r9);// xy=x[0]*y[0]
		mov(r12,rax);
		mov(r13,rdx);
		mov(rdx,w_dash);
		mul(rdx);// t=xy*p_dash
		mov(r14,rax);
		mov(rdx,mod_l);
		mul(rdx);// t128=t*mod[0]
		add(r12,rax);// Q=xy+t128
		adc(r13,rdx);
		adc(r15,0);// carry
		mov(rax,r11);// rax=x[0]
		mul(r8);// xy=x[0]*y[1]
		add(r13,rax);// Q=xy+Q[1]
		mov(rax,mod_h);
		adc(r15,rdx);
		mul(r14);// t128=t*mod[1]
		add(r13,rax);// Q+=t128
		adc(r15,rdx);

		mov(rax,ptr[rcx]);
		mov(r11,rax);
		mul(r9);// xy=x[1]*y[0]
		add(rax,r13);// xy+=Q[0]
		adc(rdx,0);
		mov(r13,rax);
		mov(r14,rdx);
		mov(r9,w_dash);
		mul(r9);// t=xy[0]*w_dash
		mov(r9,rax);
		mov(rdx,mod_l);
		mul(rdx);// t128=t*mod[0]
		xor_(r12,r12);
		add(r13,rax);// Q=xy+t128
		adc(r14,rdx);
		adc(r12,0);// carry
		mov(rax,r11);
		mul(r8);// xy=x[1]*y[1]
		mov(r11,rax);
		mov(r8,rdx);
		mov(rax,mod_h);
		mul(r9);// t128=t*mod[1]
		add(r11,rax);// ret=xy+t128
		adc(r8,rdx);
		add(r11,r15);// ret=xy+_z
		adc(r8,0);
		add(r11,r14);// ret+=Q[1]
		adc(r8,r12);

		mov(rax,mod_h);
		mov(rdx,mod_l);
		cmp(r8,rax);
		ja("mod");
		jb("exit");
		cmp(r11,rdx);
		jb("exit");
	L("mod");
		sub(r11,rdx);
		sbb(r8,rax);
	L("exit");
		mov(ptr[rcx],r8);
		mov(ptr[r10],r11);
		pop(r15);
		pop(r14);
		pop(r13);
		pop(r12);
		ret();
	}
};

struct AsmMDMulX:public Xbyak::CodeGenerator{
	// void func(*x[rcx],y_h[rdx],y_l[r8])
	// COST: push(3),pop(3),mov(25),xor(2),mul(10),add(8),adc(10),sub(1),sbb(1),cmp(2),jmp(3)
	AsmMDMulX(ull mod_h,ull mod_l,ull w_dash){
		push(r12);
		push(r13);
		push(r14);
		mov(rax,ptr[rcx]);// rax=x[0]
		mov(r9,rdx);
		mov(r11,rax);
		mul(r8);// xy=x[0]*y[0]
		xor_(r14,r14);
		mov(r10,rdx);
		mov(r12,rax);
		mov(rdx,w_dash);
		mul(rdx);// t=xy*p_dash
		mov(r13,rax);
		mov(rdx,mod_l);
		mul(rdx);// t128=t*mod[0]
		add(r12,rax);// Q=xy+t128
		adc(r10,rdx);
		adc(r14,0);// carry
		mov(rax,r11);// rax=x[0]
		mul(r9);// xy=x[0]*y[1]
		add(r10,rax);// Q=xy+Q[1]
		mov(rax,mod_h);
		adc(r14,rdx);
		mul(r13);// t128=t*mod[1]
		add(r10,rax);// Q+=t128
		adc(r14,rdx);

		mov(rax,ptr[rcx+8]);// rax=x[1]
		mov(r11,rax);
		mul(r8);// xy=x[1]*y[0]
		add(rax,r10);// xy+=Q[0]
		adc(rdx,0);
		mov(r12,rax);
		mov(r13,rdx);
		mov(r10,w_dash);
		mul(r10);// t=xy[0]*w_dash
		mov(r10,rax);
		mov(rdx,mod_l);
		mul(rdx);// t128=t*mod[0]
		xor_(r8,r8);
		add(r12,rax);// Q=xy+t128
		adc(r13,rdx);
		adc(r8,0);// carry
		mov(rax,r11);
		mul(r9);// xy=x[1]*y[1]
		mov(r9,rax);
		mov(r11,rdx);
		mov(rax,mod_h);
		mul(r10);// t128=t*mod[1]
		add(r9,rax);// ret=xy+t128
		adc(r11,rdx);
		add(r9,r14);// ret=xy+_z
		adc(r11,0);
		add(r9,r13);// ret+=Q[1]
		adc(r11,r8);

		mov(rax,mod_h);
		mov(rdx,mod_l);
		cmp(r11,rax);
		ja("mod");
		jb("exit");
		cmp(r9,rdx);
		jb("exit");
	L("mod");
		sub(r9,rdx);
		sbb(r11,rax);
	L("exit");
		mov(ptr[rcx+8],r11);
		mov(ptr[rcx],r9);
		pop(r14);
		pop(r13);
		pop(r12);
		ret();
	}
};

struct AsmFpInvertX:public Xbyak::CodeGenerator{
	// zl[rax] func(&zh[rcx],yl[rdx])
	AsmFpInvertX(ull mod_h,ull mod_l){
		push(r12);
		push(r13);
		push(r14);
		push(r15);
		mov(r8,ptr[rcx]);// y[1]
		mov(rax,0);// u[0]
		mov(r9,0);// u[1]
		mov(r10,1);// v[0]
		mov(r11,0);// v[1]
		mov(r12,0);// k
		mov(r14,mod_l);// x[0]
		mov(r15,mod_h);// x[1]

	L("loop_1_check");
		cmp(rdx,0);
		jne("loop_1");
		cmp(r8,0);
		je("loop_2");
	L("loop_1");
		mov(r13,r14);
		and_(r13,1);
		jze("y_zero_check");
		shrd(r14,r15,1);
		shr(r15,1);
		shld(r11,r10,1);
		add(r10,r10);
		jmp("loop_1_end");
	L("y_zero_check");
		mov(r13,rdx);
		and_(r13,1);
		jze("x_greater_y_check");
		shrd(rdx,r8,1);
		shr(r8,1);
		shld(r9,rax,1);
		add(rax,rax);
		jmp("loop_1_end");
	L("x_greater_y_check");
		cmp(r15,r8);
		ja("x_greater_y_proc");
		jb("y_greater_x_proc");
		cmp(rdx,r14);
		jae("y_greater_x_proc");
	L("x_greater_y_proc");
		sub(r14,rdx);
		sbb(r15,r8);
		shrd(r14,r15,1);
		shr(r15,1);
		sub(rax,r10);
		sbb(r9,r11);
		shld(r11,r10,1);
		add(r10,r10);
		jmp("loop_1_end");
	L("y_greater_x_proc");
		sub(rdx,r14);
		sbb(r8,r15);
		shrd(rdx,r8,1);
		shr(r8,1);
		sub(r10,rax);
		sbb(r11,r9);
		shld(r9,rax,1);
		add(rax,rax);
	L("loop_1_end");
		inc(r12);
		jmp("loop_1_check");
	L("loop_2");
		// todo

		pop(r15);
		pop(r14);
		pop(r13);
		pop(r12);
		ret();
	}
};

struct Asm:public Xbyak::CodeGenerator{
	Asm(){
		cmp(rdx,0);
		je("end");

		mov(rax,ptr[rcx]);
		mov(rdx,ptr[rcx+8]);

		shld(rdx,rax,1);
		add(rax,rax);

		mov(ptr[rcx],rax);
		mov(ptr[rcx+8],rdx);
	L("end");
		ret();
	}
};

int main(){
	// “ú–{Œê
	ull x[2],y=0;
	x[1]=1;
	x[0]=9223372036854775808ULL;
	Asm a;
	void (*as)(ull *,ull)=(void (*)(ull *,ull))a.getCode();
	as(x,y);
	cout<<x[1]<<" "<<x[0]<<endl;
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerj
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerjhgrewa
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerjhgrewa
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerjhgrewa
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerjhgrewa
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerjhgrewa
	jjohgaejojhnharwoeijawerjhjjhboiawerjoihjaeroijgohiaerjhgrewa
	jjohgaejojhnharwoeija
}