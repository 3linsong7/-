// 3_10.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

int main(int argc, char* argv[])
{
	FILE *fp;
	int len;
	int* ptr;
	fp = fopen("C:/WINDOWS/system32/notepad.exe","r");
	if(fp == NULL){
		printf("ÎÄ¼þ´íÎó£¡");
		return 0;
	}
	fseek(fp,0,SEEK_END);
	len = ftell(fp);
	fclose(fp);
	ptr = (int*)malloc(len);
	if(ptr == NULL){
		return 0;
	}
	memset(ptr,0,len);
	printf("%p\n",ptr);
	free(ptr);
	ptr = NULL;
	return 0;
}

