// 3_4.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

int main(int argc, char* argv[])
{
	int arr[4][4] = {
		{1,2,3,4},
		{5,6,7,8},
		{9,10,11},
		{12,13,14,15}
	};
	int (*px)[4];
	px = (int (*)[4])arr;
	printf("%d %d",*(px + 1)[2],px[1][2]);

	return 0;
}

