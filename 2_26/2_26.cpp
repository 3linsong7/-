// 2_26.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

struct Student{
	int x;
	int y;
};

void fun1(){
	Student***** s;
	s = (Student*****)100;
	s++;	//104
	printf("%d\n",s);
	s = s + 2;	//112
	printf("%d\n",s);
	s = s - 3;	//100
	printf("%d\n",s);
}

void fun2(){
	Student**** s1;
	Student**** s2;
	int x;
	s1 = (Student****)200;
	s2 = (Student****)100;
	x = s1 - s2;	//25
	printf("%d\n",x);
}

void fun3(){
	Student* s;
	s = (Student*)100;
	s++;	//112
	printf("%d\n",s);
	s = s + 2;	//136
	printf("%d\n",s);
	s = s - 3;	//100
	printf("%d\n",s);
}

void fun4(){
	Student* s1;
	Student* s2;
	s1 = (Student*)200;
	s2 = (Student*)100;
	int x;	//12
	x = s1 - s2;
	printf("%d\n",x);
}

int main(int argc, char* argv[])
{
	//fun1();
	//fun2();
	//fun3();
	fun4();
	return 0;
}

