// 3_3.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

//1������һ��int* arr[5] ���飬��Ϊ���鸳ֵ(ʹ��&).
void fun1(){
	int* arr[5];
//	*(arr) = (int*)1;
	char x = 'a';
	*(arr) = (int*)x;
	printf("%d\n",*(arr));
}

//2������һ���ַ�ָ�����飬�洢���е�C�Ĺؼ���(��������)����ȫ����ӡ����.
int fun2(){
	char* arr1[] = {
		"auto","break","case","char","const","continue","default","do","double","else",
		"enum","extern","float","for","goto","if","int","long","register","return",
		"short","signed","sizeof","static","struct","switch","typedef","unsigned","union","void",
		"volatile","while",'\0'
	};
	int y = 0;
	int i = 0;
	while(*(arr1 + i) != 0){
		y++;
		i++;
	}
	for(i = 0;i < y;i++){
		printf("%s\t",*(arr1 + i));
	}
	return 0;
}
//3��������Щ�����У��м���id=1 level=8�Ľṹ����Ϣ��
char arr[] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x07,0x09,					
	0x00,0x20,0x10,0x03,0x03,0x0C,0x00,0x00,0x44,0x00,					
	0x00,0x33,0x01,0x00,0x00,0x08,0x00,0x00,0x00,0x00,					
	0x00,0x00,0x00,0x02,0x64,0x00,0x00,0x00,0xAA,0x00,					
	0x00,0x00,0x64,0x01,0x00,0x00,0x00,0x08,0x00,0x00,					
	0x00,0x00,0x02,0x00,0x74,0x0F,0x41,0x00,0x00,0x00,					
	0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x0A,0x00,					
	0x00,0x02,0x57,0x4F,0x57,0x00,0x06,0x08,0x00,0x00,					
	0x00,0x00,0x00,0x64,0x00,0x0F,0x00,0x00,0x0D,0x00,					
	0x00,0x00,0x23,0x00,0x00,0x64,0x00,0x00,0x64,0x00					

};

typedef struct TagPlayer		
{		
	int id;	
	int level;	
}Player;

int fun3(){
	//printf("%x\n",&arr[0]);
	Player p;
	p.id = 1;
	p.level = 8;
	Player* px = &p;
	int len = sizeof(arr) - sizeof(0);
	int i;
	printf("id = 1:");
	for(i = 0;i < len;i++){
		if(*(arr + i) == px->id){
			printf("%x\n",&arr[i]);
		}
	}
	printf("\n");
	printf("level = 8:");
	for(i = 0;i < len;i++){
		if(*(arr + i) == px->level){
			printf("%x\n",&arr[i]);
		}
	}
	return 0;
}		


int main(int argc, char* argv[])
{
	//fun1();
	//fun2();
	fun3();
	return 0;
}

