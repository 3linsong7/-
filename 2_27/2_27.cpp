// 2_27.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

void fun1(){
	char a = 10;
	short b = 20;
	int c = 30;
	char* pa = &a;
	short* pb = &b;
	int* pc = &c;
	char** ppa = &pa;
	short** ppb = &pb;
	int** ppc = &pc;
}

void fun2(){
	int p = 10;
	int******* p7;
	int****** p6;
	int***** p5;
	int**** p4;
	int*** p3;
	int** p2;
	int* p1;

	p1 = &p;
	p2 = &p1;
	p3 = &p2;
	p4 = &p3;
	p5 = &p4;
	p6 = &p5;
	p7 = &p6;

}

int main(int argc, char* argv[])
{
	//fun1();
	fun2();
	return 0;
}

