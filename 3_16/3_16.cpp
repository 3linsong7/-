// 3_16.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "stdio.h"
#include "windows.h"
#include "stdlib.h"
#include "malloc.h"
#include "string.h"

//�����ļ���С��ȡ
int ReadPeFile(char* File_path,PVOID* FileBuffer){
	FILE* PeFi;
	unsigned int Fi_size = 0;
	//LPVOID ��ָ��void *
	LPVOID PeData = NULL;
	PeFi = fopen(File_path,"rb");
	if(!PeFi){
		printf("�ļ���ʧ�ܣ�");
		return 0;
	}
	fseek(PeFi,0,SEEK_END);
	Fi_size = ftell(PeFi);
	fseek(PeFi,0,SEEK_SET);
	PeData = malloc(Fi_size);
	if(!PeData){
		printf("�����ڴ�ʧ�ܣ�");
		fclose(PeFi);
		return 0;
	}
	size_t n = fread(PeData,Fi_size,1,PeFi);
	if(!n){
		printf("��ȡ�ڴ�ʧ�ܣ�");
		fclose(PeFi);
		free(PeData);
		return 0;
	}
	*FileBuffer = PeData;
	PeData = NULL;
	fclose(PeFi);
	return Fi_size;
}

//����FileBuffer�ڴ��������FilerBuffer��
int CopyFileBuffer(PVOID FileBuffer,PVOID* ImageBuffer){
	//��ʼ��ͷ���ļ�
	PIMAGE_DOS_HEADER PdosHeader = NULL;
	PIMAGE_NT_HEADERS PntHeader = NULL;
	PIMAGE_FILE_HEADER PfileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER PoptionHeader = NULL;
	PIMAGE_SECTION_HEADER PsectionHeader = NULL;
	//��ʼ��imagebufferָ��
	LPVOID pTempImageBuffer = NULL;
	int i;
	if(!FileBuffer){
		printf("FileBuffer�ڴ��ȡʧ�ܣ�");
		return 0;
	}
	PdosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PntHeader = (PIMAGE_NT_HEADERS)((DWORD)FileBuffer + PdosHeader->e_lfanew);
	PfileHeader = (PIMAGE_FILE_HEADER)((DWORD)PntHeader + 4);
	PoptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)PfileHeader + 20);
	PsectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)PoptionHeader + PfileHeader->SizeOfOptionalHeader);
	//�����ڴ�ռ�
	pTempImageBuffer = malloc(PoptionHeader->SizeOfImage);
	//��ʼ���ߴ�
	memset(pTempImageBuffer,0,PoptionHeader->SizeOfImage);
	//����ͷ�ļ�
	memcpy(pTempImageBuffer,PdosHeader,PoptionHeader->SizeOfHeaders);
	PIMAGE_SECTION_HEADER pTempSectionHeader = PsectionHeader;
	for(i = 0;i < PfileHeader->NumberOfSections;i++,pTempSectionHeader++){
		memcpy((void*)((DWORD)pTempImageBuffer + pTempSectionHeader->VirtualAddress),(void*)((DWORD)FileBuffer + pTempSectionHeader->PointerToRawData),pTempSectionHeader->SizeOfRawData);
	}
	*ImageBuffer = pTempImageBuffer;
	pTempImageBuffer = NULL;
	return PoptionHeader->SizeOfImage;
}

//����imagebufferѹ������newbuffer��
int CopyImageBuffer(PVOID ImageBuffer,PVOID* NewBuffer){
	PIMAGE_DOS_HEADER PdosHeader = NULL;
	PIMAGE_NT_HEADERS PntHeader = NULL;
	PIMAGE_FILE_HEADER PfileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER PoptionHeader = NULL;
	PIMAGE_SECTION_HEADER PsectionHeader = NULL;
	LPVOID pTempNewBuffer = NULL;
	int i, j;
	if(!ImageBuffer){
		printf("�ڴ�Ϊ�գ�");
		return 0;
	}
	PdosHeader = (PIMAGE_DOS_HEADER)ImageBuffer;
	PntHeader = (PIMAGE_NT_HEADERS)((DWORD)PdosHeader + PdosHeader->e_lfanew);
	PfileHeader = (PIMAGE_FILE_HEADER)((DWORD)PntHeader + 4);
	PoptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)PfileHeader + 20);
	PsectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)PoptionHeader + PfileHeader->SizeOfOptionalHeader);
	int NewBuffer_size = PoptionHeader->SizeOfHeaders;
	for(i = 0;i < PfileHeader->NumberOfSections;i++){
		NewBuffer_size += PsectionHeader[i].SizeOfRawData;
	}
	//�����ڴ�ռ�
	pTempNewBuffer = malloc(NewBuffer_size);
	//��ʼ���ڴ�
	memset(pTempNewBuffer,0,NewBuffer_size);
	//����ͷ�ļ�
	memcpy(pTempNewBuffer,PdosHeader,PoptionHeader->SizeOfHeaders);
	PIMAGE_SECTION_HEADER pTempSectionHeader = PsectionHeader;
	for(j = 0;j < PfileHeader->NumberOfSections;j++,pTempSectionHeader++){
		memcpy((void*)((DWORD)pTempNewBuffer + pTempSectionHeader->PointerToRawData),(void*)((DWORD)ImageBuffer + pTempSectionHeader->VirtualAddress),pTempSectionHeader->SizeOfRawData);
	}
	*NewBuffer = pTempNewBuffer;
	pTempNewBuffer = NULL;
	return NewBuffer_size;
}

int NewBuffer_write_exe(PVOID NewBuffer,int ret3,char* Write_File_path){
	FILE* fp;
	fp = fopen(Write_File_path,"wb");
	if(fp != NULL){
		fwrite(NewBuffer,ret3,1,fp);
	}
	fclose(fp);
	return 1;
}

int Info(){
	//PVOID�ȼ���void *
	PVOID FileBuffer = NULL;
	PVOID ImageBuffer = NULL;
	PVOID NewBuffer = NULL;
	char File_path[] = "C:/fg/fg.exe";
	char Write_File_path[] = "C:/fg/file1.exe";
	int ret1 = ReadPeFile(File_path,&FileBuffer); //&FileBuffer�ȼ���**FileBuffer
	printf("exe -> FileBuffer ���ڴ��С��%#x\n",ret1);
	int ret2 = CopyFileBuffer(FileBuffer,&ImageBuffer);
	printf("FileBuffer -> ImageBuffer ���ڴ��С��%#x\n",ret2);
	int ret3 = CopyImageBuffer(ImageBuffer,&NewBuffer);
	printf("ImageBuffer -> NewBuffer ���ڴ��С��%x\n",ret3);
	int ret4 = NewBuffer_write_exe(NewBuffer,ret3,Write_File_path);
	printf("�ļ���СΪ:%d\n",ret4);
	return 0;
}

int main(int argc, char* argv[])
{
	Info();
	return 0;
}

