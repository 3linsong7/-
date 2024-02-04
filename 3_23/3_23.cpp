// 3_23.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#pragma comment(lib,"TestDll.lib")

extern "C"_declspec(dllimport) int Plus(int x,int y);

int main(int argc, char* argv[])
{
	printf("%d\n",Plus(1,2));
	getchar();
	return 0;
}

