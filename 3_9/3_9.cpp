// 3_9.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

void fun(){
//1������һ��unsiged char ���ͣ�ͨ������Ϊ��3��5��7λ��ֵ,��ֵʱ����Ӱ�쵽����λԭ����ֵ.
	unsigned char i = 0;	//0000 0000
	i = i | 54;
	printf("%d\n",i);
//2���ж�ĳ��λ��ֵ�Ƿ�Ϊ1.
	int x = 15;		// 0001 0101
	int y = 0;
	if((x & 10) == 10){
		y = 1;
	}
	printf("%d\n",y);

}

//3����ȡ��7��6��5λ��ֵ����ʮ������ʾ(unsigned).
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

