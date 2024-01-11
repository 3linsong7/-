// 3_9.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

void fun(){
//1、定义一个unsiged char 类型，通过程序为第3、5、7位赋值,赋值时不能影响到其它位原来的值.
	unsigned char i = 0;	//0000 0000
	i = i | 54;
	printf("%d\n",i);
//2、判断某个位的值是否为1.
	int x = 15;		// 0001 0101
	int y = 0;
	if((x & 10) == 10){
		y = 1;
	}
	printf("%d\n",y);

}

//3、读取第7、6、5位的值，以十进制显示(unsigned).
void fun2(){
	unsigned char i = 46;	//0100 0101	0000 0100  0000 0001   0010 0010 0001 0001
	unsigned char a = (i >> 4) & 1;
	unsigned char b = (i >> 5) & 1;
	unsigned char c = (i >> 6) & 1;
	printf("%d %d %d\n",a,b,c);
}

int main(int argc, char* argv[])
{
	//fun();
	fun2();
	return 0;
}

