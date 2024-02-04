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
BYTE NewSection[] = {
	0x2E,0x74,0x74,0x74,0x74,0x00,0x00,0x00,0x22,0x97,
	0x01,0x00,0x00,0x10,0x00,0x00,0x00,0xA0,0x01,0x00,
	0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x60,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
char File_path[] = "C:/fg/fg.exe";
char New_File_path[] = "C:/fg/file.exe";

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

DWORD ValueToAlignment(DWORD x,DWORD alignment){
	if(x < 0)
		return 0;
	if(x <= alignment){
		return alignment;
	}
	else{
		if(x % alignment != 0){
		return alignment * (x / alignment + 1);
		}
		else{
			return x;
		}
	}
	return 0;
}

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

//����������������
int AddNewSection(PVOID FileBuffer,DWORD SizeofSection,DWORD file_size,PVOID* NewFileBuffer){
	PIMAGE_DOS_HEADER pDosHeader =NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	if(!FileBuffer){
		printf("�ļ���ȡʧ�ܣ�");
		return 0;
	}
	if(*((PWORD)FileBuffer) != IMAGE_DOS_SIGNATURE){
		printf("��ΪMZ!");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*((PDWORD)((DWORD)FileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
		printf("������Ч��PE�ļ���");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	//�ж��Ƿ���80����λ�ɽ�����ӡ�
	if((pOptionHeader->SizeOfHeaders - (pDosHeader->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + pFileHeader->SizeOfOptionalHeader + IMAGE_SIZEOF_SECTION_HEADER * pFileHeader->NumberOfSections)) < 80){
		printf("��ʣ�ռ䲻��80���޷���ӽڱ�");
		return 0;
	}
	DWORD numSec = pFileHeader->NumberOfSections;
	//���һ���µĽ�
	memcpy((void*)(pSectionHeader + numSec),(void*)(pSectionHeader),sizeof(IMAGE_SECTION_HEADER));
	//�������ں����һ���ڴ�С��000
	memset((void*)(pSectionHeader + numSec + 1),0,sizeof(IMAGE_SECTION_HEADER));
	//�޸�PEͷ�ڵ�����
	pFileHeader->NumberOfSections += 1;
	//�޸�sizeOfImage��С
	pOptionHeader->SizeOfImage += 0x1000;
	//���������ڵ�����
	//�޸Ľڱ�����
	char* NewSecName = ".Song";
	memcpy((void*)(pSectionHeader + numSec),NewSecName,sizeof(NewSecName));
	//�޸���������
	(pSectionHeader + numSec)->Misc.VirtualSize = 0x1000;
	//�޸�vadd
	(pSectionHeader + numSec)->VirtualAddress = (pSectionHeader + numSec - 1)->VirtualAddress + ValueToAlignment((pSectionHeader + numSec - 1)->Misc.VirtualSize,0x1000);
	//�޸�sizeofRa
	(pSectionHeader + numSec)->SizeOfRawData = 0x1000;
	//����PointerToRa
	(pSectionHeader + numSec)->PointerToRawData = (pSectionHeader + numSec - 1)->PointerToRawData + (pSectionHeader + numSec - 1)->SizeOfRawData;
	//��ԭ�����ݵ��������һ���ڵ�����
	//DWORD NewSize = file_size + SizeofSection;
	//PVOID pNewFileBuffer = malloc(NewSize);
	*NewFileBuffer = malloc(file_size + SizeofSection);
	//memset(pNewFileBuffer,0,NewSize);
	memcpy(*NewFileBuffer,FileBuffer,file_size);
	//*NewFileBuffer = pNewFileBuffer;
	return (pSectionHeader + numSec)->SizeOfRawData + (pSectionHeader + numSec)->PointerToRawData;
}

//������������ע��shellcode
int AddNewSecShell(PVOID NewFileBuffer,DWORD file_size){
	PVOID NewBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	if(*((PWORD)NewFileBuffer) != IMAGE_DOS_SIGNATURE){
		printf("��ΪMZ!");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)NewFileBuffer;
	if(*((PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
		printf("������Ч��PE!");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + 20);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	DWORD numSec = pFileHeader->NumberOfSections;
	if((pSectionHeader + numSec - 1)->Misc.VirtualSize < ShellcodeLen){
		printf("�ռ䲻��shellcode���ȣ�");
		return 0;
	}
	PBYTE CodeBegin = (PBYTE)((DWORD)NewFileBuffer + (pSectionHeader + numSec - 1)->PointerToRawData);
	memcpy(CodeBegin,ShellCode,ShellcodeLen);
	DWORD rva_codeBegin = (pSectionHeader + numSec - 1)->VirtualAddress;
	char* Image_CodeBegin = (char*)((pSectionHeader + numSec - 1)->VirtualAddress + pOptionHeader->ImageBase);
	char* CALLADDR = (char*)Image_CodeBegin + 0x8;
	*(PDWORD)(CodeBegin + 0x9) = MESSAGEBOXADDR - (DWORD)CALLADDR - 5;
	char* JMPADDR = (char*)CALLADDR + 0X5;
	char* OEPADDR = (char*)(pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint);
	*(PDWORD)(CodeBegin + 0x9 + 0x5) = (DWORD)OEPADDR - (DWORD)JMPADDR - 5;
	pOptionHeader->AddressOfEntryPoint = rva_codeBegin;
	printf("SHELLCODE��ӳɹ���\n");
	/*DWORD CALLADDR = (MESSAGEBOXADDR - ((PBYTE)(Image_CodeBegin + 0xD)));
	*(PDWORD)(CodeBegin + 0x9) = CALLADDR;
	DWORD JMPADDR = ((pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - ((PBYTE)(Image_CodeBegin + ShellcodeLen)));
	*(PDWORD)(CodeBegin + 0x9 + 0x5) = JMPADDR;
	pOptionHeader->AddressOfEntryPoint = rva_codeBegin;
/*	PBYTE CodeBegin = (PBYTE)((DWORD)NewFileBuffer + (pSectionHeader + (pFileHeader->NumberOfSections - 1))->VirtualAddress + (pSectionHeader + (pFileHeader->NumberOfSections - 1))->Misc.VirtualSize);
	memcpy(CodeBegin,ShellCode,ShellcodeLen);
	//E8�޸�
	DWORD CALLADDR = (MESSAGEBOXADDR - (pOptionHeader->ImageBase + ((DWORD)(CodeBegin + 0xD) - (DWORD)NewFileBuffer)));
	*(PDWORD)(CodeBegin + 0x9) = CALLADDR;
	//E9�޸�
	DWORD JMPADDR = ((pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - (pOptionHeader->ImageBase + ((DWORD)(CodeBegin + ShellcodeLen) - (DWORD)NewFileBuffer)));
	*(PDWORD)(CodeBegin + 0xE) = JMPADDR;
	//�޸�OEP
	pOptionHeader->AddressOfEntryPoint = (DWORD)CodeBegin - (DWORD)NewFileBuffer;*/
	/*size_t New_size = CopyNewBuffer(NewFileBuffer,&NewBuffer);
	if(!New_size){
		printf("New_size��Ч��");
		return 0;
	}
	int y = WriteFilePath(NewBuffer,New_size,New_File_path);
	if(!y){
		printf("����ʧ�ܣ�");
		return 0;
	}*/
	file_size += 0x1000;
	FILE *fp;
	fp = fopen(New_File_path,"wb");
	if(!fp){
		printf("new_file��ʧ�ܣ�");
		return 0;
	}
	fwrite(NewFileBuffer,file_size,1,fp);
	printf("���̳ɹ���");
	return 0;
}

int AddOneSec(){
	PVOID FileBuffer = NULL;
	PVOID NewFileBuffer = NULL;
	PVOID ImageBuffer = NULL;
	DWORD file_size = ReadFileBuffer(File_path,&FileBuffer);
	DWORD SizeofSection_Add = AddNewSection(FileBuffer,0x1000,file_size,&NewFileBuffer);
	printf("%#x\n",SizeofSection_Add);
	//CopyImageBuffer(NewFileBuffer,&ImageBuffer);
	AddNewSecShell(NewFileBuffer,file_size);
	return 0;
}

//��ѯ����ֵ�
int TestPrintDirectory(){
	PVOID FileBuffer = NULL;
	ReadFileBuffer(File_path,&FileBuffer);
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	if(*(PWORD)FileBuffer != IMAGE_DOS_SIGNATURE){
		printf("������ЧMZ��");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*(PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE){
		printf("������ЧPE�ļ���");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + 20);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_DATA_DIRECTORY pDirectoryAddr = pOptionHeader->DataDirectory;
	printf("�������ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("������ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("��Դ���ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("�쳣��Ϣ���ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("��ȫ֤����ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("�ض�λ���ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("������Ϣ���ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("��Ȩ���Ա��ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("ȫ��ָ����ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("TLS���ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("�������ñ��ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("�󶨵�����ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("IAT���ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("�ӳٵ�����ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("COM��Ϣ���ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("������ַ��%#x\t\t��С��%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	return 0;
}

int main(int argc, char* argv[])
{
	//Info();
	//����shellcode���
	//TestShellcode();
	//��������
	//AddOneSec();
	//��ѯ�������
	TestPrintDirectory();
	getchar();
	return 0;
}

