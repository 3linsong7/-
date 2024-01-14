// 3_18.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "stdio.h"
#include "windows.h"
#include "malloc.h"

#define ShellcodeLen	0X12
#define MESSAGEBOXADDR	0X77D507EA
BYTE ShellCode[] = {
	0X6A,0X00,0X6A,0X00,0X6A,0X00,0X6A,0X00,
	0XE8,0X00,0X00,0X00,0X00,
	0XE9,0X00,0X00,0X00,0X00
};

//���ļ���С
int ReadFileBuffer(char* file_path,PVOID* FileBuffer){
	FILE* fp;
	unsigned int file_size = NULL;
	LPVOID TempFileBuffer = NULL;
	fp = fopen(file_path,"rb");
	if(!fp){
		printf("�ļ���ʧ�ܣ�");
		return 0;
	}
	fseek(fp,0,SEEK_END);
	file_size = ftell(fp);
	fseek(fp,0,SEEK_SET);
	if(!file_size){
		printf("�ļ���СΪ�գ�");
		return 0;
	}
	TempFileBuffer = malloc(file_size);
	if(!TempFileBuffer){
		printf("��ʼ���ڴ�ʧ�ܣ�");
		return 0;
	}
	size_t n = fread(TempFileBuffer,file_size,1,fp);
	if(!n){
		printf("��ȡ�ڴ�ʧ�ܣ�");
		return 0;
	}
	*FileBuffer = TempFileBuffer;
	TempFileBuffer = NULL;
	fclose(fp);
	return file_size;
}

//��FileBuffer��������
DWORD CopyImageBuffer(PVOID FileBuffer,PVOID* ImageBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID TempImageBuffer = NULL;
	int i;
	if(!FileBuffer){
		printf("FileBuffer�ڴ�Ϊ�գ�");
		return 0;
	}
	if(*((PWORD)FileBuffer) != IMAGE_DOS_SIGNATURE){
		printf("dosͷ��ΪMZ��");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*((PDWORD)((DWORD)FileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
		printf("������Ч��PE�ļ���");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)FileBuffer + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	//��ʼ����С
	TempImageBuffer = malloc(pOptionHeader->SizeOfImage);
	if(!TempImageBuffer){
		printf("��ʼ��ʧ�ܣ�");
		return 0;
	}
	//�����ڴ����
	memset(TempImageBuffer,0,pOptionHeader->SizeOfImage);
	//����ͷ�ļ�����
	memcpy(TempImageBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for(i = 0;i < pFileHeader->NumberOfSections;i++,pTempSectionHeader++){
		//���н��ļ����츴��
		memcpy((void*)((DWORD)TempImageBuffer + pTempSectionHeader->VirtualAddress),(void*)((DWORD)FileBuffer + pTempSectionHeader->PointerToRawData),pTempSectionHeader->SizeOfRawData);
	}
	*ImageBuffer = TempImageBuffer;
	TempImageBuffer = NULL;
	return pOptionHeader->SizeOfImage;
}

//��ImageBuffer��С����ѹ��
DWORD CopyNewBuffer(PVOID ImageBuffer,PVOID* NewBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID TempNewBuffer = NULL;
	int i,j;
	if(!ImageBuffer){
		printf("ImageBuffer����Ϊ�գ�");
		return 0;
	}
	if(*((PWORD)ImageBuffer) != IMAGE_DOS_SIGNATURE){
		printf("����һ����ЧMZ��");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)ImageBuffer;
	if(*((PDWORD)((DWORD)ImageBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
		printf("����һ����ЧPE��");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	int New_size = pOptionHeader->SizeOfHeaders;
	for(i = 0;i < pFileHeader->NumberOfSections;i++){
		New_size += pSectionHeader[i].SizeOfRawData;
	}
	//��ʼ����С
	TempNewBuffer = malloc(New_size);
	//�����ڴ�
	memset(TempNewBuffer,0,New_size);
	//����ͷ�ļ�
	memcpy(TempNewBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for(j = 0;j < pFileHeader->NumberOfSections;j++,pTempSectionHeader++){
		memcpy((void*)((DWORD)TempNewBuffer + pTempSectionHeader->PointerToRawData),(void*)((DWORD)ImageBuffer + pTempSectionHeader->VirtualAddress),pTempSectionHeader->SizeOfRawData);
	}
	*NewBuffer = TempNewBuffer;
	TempNewBuffer = NULL;
	return New_size;
}

//����д�ļ�
DWORD WriteFilePath(PVOID NewBuffer,size_t New_Size,char* write_file_path){
	FILE *fp;
	fp = fopen(write_file_path,"wb+");
	if(!fp){
		printf("�ļ���ʧ�ܣ�");
		return 0;
	}
	fwrite(NewBuffer,New_Size,1,fp);
	fclose(fp);
	return 1;
}
/*
int Info(){
//	PVOID FileBuffer = NULL;
//	PVOID ImageBuffer = NULL;
//	PVOID NewBuffer = NULL;
//	int New_size;
//	char file_path[] = "C:/fg/fg.exe";
//	char write_file_path[] = "C:/fg/file.exe";
	//���ж��ļ���С.
	int ret1 = ReadFileBuffer(file_path,&FileBuffer);
	printf("ret1�ڴ��СΪ%x\n",ret1);
	//����filebuffer��չ��filebuffer->imagebuffer.
	int ret2 = CopyImageBuffer(FileBuffer,&ImageBuffer);
	printf("ret2�ڴ��СΪ%x\n",ret2);
	//����imagebufferѹ����imagebuffer->newbuffer.
	New_size = CopyNewBuffer(ImageBuffer,&NewBuffer);
	printf("New_size���ڴ��СΪ%x\n",New_size);
	//�����ļ����棬newbuffer-> xin.exe
	WriteFilePath(NewBuffer,New_size,write_file_path);
	return 0;
}
*/

int TestShellcode(){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PVOID FileBuffer = NULL;
	PVOID ImageBuffer = NULL;
	PVOID NewBuffer = NULL;
	size_t New_size = NULL;
	char file_path[] = "C:/fg/fg.exe";
	char write_file_path[] = "C:/fg/file.exe";
	//�����ļ���ȡ
	ReadFileBuffer(file_path,&FileBuffer);
	if(!FileBuffer){
		printf("�ļ���ȡʧ�ܣ�");
		return 0;
	}
	//����filebuffer�ļ�����
	CopyImageBuffer(FileBuffer,&ImageBuffer);
	if(!ImageBuffer){
		printf("filebuffer�ڴ�����ʧ�ܣ�");
		free(FileBuffer);
		return 0;
	}
	if(*((PWORD)ImageBuffer) != IMAGE_DOS_SIGNATURE){
		printf("��ΪMZ");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)ImageBuffer;
	if(*((PDWORD)((DWORD)ImageBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
		printf("���ļ�������Чpe�ļ���");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	if((pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize) < ShellcodeLen){
		printf("����ռ���������");
		free(FileBuffer);
		free(ImageBuffer);
		return 0;
	}
	PBYTE CodeBegin = (PBYTE)((DWORD)ImageBuffer + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
	memcpy(CodeBegin,ShellCode,ShellcodeLen);
	printf("codebegin:%#x\n",CodeBegin);
	//E8����
	DWORD CALLADDR = (MESSAGEBOXADDR - (pOptionHeader->ImageBase +((DWORD)(CodeBegin + 0xD) - (DWORD)ImageBuffer)));
	printf("CALLADDR:%#x\n",CALLADDR);
	*(PDWORD)(CodeBegin + 0x9) = CALLADDR;
	printf("CodeBegin+0x9:%#x\n",*(PDWORD)(CodeBegin+0x9));
	//E9����
	DWORD JMPADDR = ((pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - (pOptionHeader->ImageBase + ((DWORD)(CodeBegin + ShellcodeLen) - (DWORD)ImageBuffer)));
	*(PDWORD)(CodeBegin + 0xE) = JMPADDR;
	//�޸�OEP
	pOptionHeader->AddressOfEntryPoint = (DWORD)CodeBegin - (DWORD)ImageBuffer;
	New_size = CopyNewBuffer(ImageBuffer,&NewBuffer);
	if(!New_size){
		printf("new_size��Ч��");
		return 0;
	}
	int y = WriteFilePath(NewBuffer,New_size,write_file_path);
	if(!y){
		printf("����ʧ�ܣ�");
		return 0;
	}
	printf("���̳ɹ���");
	free(FileBuffer);
	free(ImageBuffer);
	free(NewBuffer);
	return 0;
}

int main(int argc, char* argv[])
{
	//Info();
	//����shellcode���
	TestShellcode();
	getchar();
	return 0;
}

