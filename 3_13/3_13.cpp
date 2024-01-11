// 3_12.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"

//文件读取
char* ReadPeFile(char* PeFIle){
	FILE* PeFile;
	PeFile = fopen(PeFIle,"rb");
	unsigned int len = 0;
	char* PeData = NULL;
	if(PeFile == NULL){
		printf("ERROR!");
		return 0;
	}
	fseek(PeFile,0,SEEK_END);
	len = ftell(PeFile);
	fseek(PeFile,0,SEEK_SET);
	PeData = (char*)malloc(len);
	if(PeData != NULL){
		memset(PeData,'0',len);
		fread(PeData,sizeof(char),len,PeFile);
	}
	return PeData;
}

//中转
void Info(char* PeF){
	int i;
	char* PeData = ReadPeFile(PeF);
	PIMAGE_DOS_HEADER pDos_header = NULL;
	PIMAGE_NT_HEADERS pNt_header = NULL;
	PIMAGE_FILE_HEADER pFile_header = NULL;
	PIMAGE_OPTIONAL_HEADER pOption_header = NULL;
	PIMAGE_SECTION_HEADER pSection_header = NULL;
	pDos_header = (PIMAGE_DOS_HEADER)PeData;
	pNt_header = (PIMAGE_NT_HEADERS)(PeData+pDos_header->e_lfanew);
	pFile_header = (PIMAGE_FILE_HEADER)(PeData+pDos_header->e_lfanew+4);
	pOption_header = (PIMAGE_OPTIONAL_HEADER)(PeData+pDos_header->e_lfanew+24);
	pSection_header = (PIMAGE_SECTION_HEADER)((DWORD)pOption_header+pFile_header->SizeOfOptionalHeader);
	for(i = 0;i < pFile_header->NumberOfSections;i++){
		printf("第%d个节表\n",i+1);
		printf("Name = %s\n",pSection_header->Name);
		printf("Misc = %x\n",pSection_header->Misc);
		printf("VirtualAddress = %x\n",pSection_header->VirtualAddress);
		printf("SizeOfRawData = %x\n",pSection_header->SizeOfRawData);
		printf("PointerToRawData = %x\n",pSection_header->PointerToRawData);
		printf("PointerToRelocations = %x\n",pSection_header->PointerToRelocations);
		printf("PointerToLinenumbers = %x\n",pSection_header->PointerToLinenumbers);
		printf("NumberOfRelocations = %x\n",pSection_header->NumberOfRelocations);
		printf("NumberOfLinenumbers = %x\n",pSection_header->NumberOfLinenumbers);
		printf("Characteristics = %x\n",pSection_header->Characteristics);
		pSection_header += 1;
	}
	free(PeData);
}

int main(int argc, char* argv[])
{
	Info("C:/fg/fg.exe");
	return 0;
}

