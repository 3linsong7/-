// 3_18.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "stdio.h"
#include "windows.h"
#include "malloc.h"
#include "stdlib.h"

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
//char File_path[] = "C:/fg/fg.exe";
char File_path[] = "C:/fg/notepad.exe";
char New_File_path[] = "C:/fg/file.dll";

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
	printf("�ļ�����ɹ���");
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

//ͷ����
int HeaderSize(PVOID FileBuffer,PIMAGE_DOS_HEADER& pDosHeader,PIMAGE_NT_HEADERS& pNtHeader,PIMAGE_FILE_HEADER& pFileHeader,
			   PIMAGE_OPTIONAL_HEADER& pOptionHeader,PIMAGE_SECTION_HEADER& pSectionHeader){
	if(!FileBuffer){
		printf("�ļ��ڴ�Ϊ�գ�");
		return 0;
	}
	if(*(PWORD)FileBuffer != IMAGE_DOS_SIGNATURE){
		printf("������ЧMZ��");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*(PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE){
		printf("������ЧPE��");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	return 0;
}

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

//RVA---->FOA
DWORD RVAToFOA(PVOID FileBuffer,DWORD RVA){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	int i;
	if(*(PWORD)FileBuffer != IMAGE_DOS_SIGNATURE){
		printf("������ЧMZ!");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*(PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE){
		printf("������ЧPE!");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	if(RVA <= pOptionHeader->SizeOfHeaders){
		return RVA;
	}
	for(i = 0;i < pFileHeader->NumberOfSections;i++){
		if(RVA >= (pSectionHeader + i)->VirtualAddress && RVA < ((pSectionHeader + i)->VirtualAddress + (pSectionHeader + i)->Misc.VirtualSize)){
			return ((pSectionHeader + i)->PointerToRawData + (RVA - (pSectionHeader + i)->VirtualAddress));
		}
	}
	return 0;
}

int FOAToRVA(PVOID FileBuffer,DWORD FOA){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	if(FOA <= pOptionHeader->SizeOfHeaders){
		return FOA;
	}
	for(int i = 0;i < pFileHeader->NumberOfSections;i++){
		if(FOA >= pSectionHeader[i].PointerToRawData && FOA < (pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData)){
			return (FOA - pSectionHeader[i].PointerToRawData + pSectionHeader[i].VirtualAddress);
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

//�������תվ
int AddOneSec(){
	PVOID FileBuffer = NULL;
	PVOID NewFileBuffer = NULL;
	PVOID ImageBuffer = NULL;
	DWORD file_size = ReadFileBuffer(File_path,&FileBuffer);
	DWORD SizeofSection_Add = AddNewSection(FileBuffer,0x1000,file_size,&NewFileBuffer);
	printf("%#x\n",SizeofSection_Add);
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

//��ӡ��������Ϣ
int PrintExport(PVOID FileBuffer){
	if(!FileBuffer){
		printf("�ļ���ȡʧ�ܣ�");
		return 0;
	}
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DWORD i;
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
	PIMAGE_DATA_DIRECTORY pDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionHeader->DataDirectory);
	if(!pDirectory->VirtualAddress){
		printf("�ó���û�е�����");
		return 0;
	}
	printf("������RVA��%#x\n",pDirectory->VirtualAddress);
	DWORD ExportFOA = RVAToFOA(FileBuffer,pOptionHeader->DataDirectory[0].VirtualAddress); 
	if(ExportFOA){
		printf("������FOA��%#x\n",ExportFOA);
	}
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ExportFOA + (DWORD)FileBuffer);
	printf("\n\n---------------------��ӡ������ṹ---------------------\n\n");
	//printf("�ļ���Ϊ��%s\n",ExportDirectory->Name);
	printf("Characteristics:%x\n",ExportDirectory->Characteristics);
	printf("TimeDateStamp:%x\n",ExportDirectory->TimeDateStamp);
	printf("Name:%x\n",ExportDirectory->Name);
	printf("Name:%s\n",((DWORD)FileBuffer + ExportDirectory->Name));
	printf("Base:%x\n",ExportDirectory->Base);
	printf("NumberOfFunctions:%x\n",ExportDirectory->NumberOfFunctions);
	printf("NumberOfNames:%x\n",ExportDirectory->NumberOfNames);
/*	printf("\n\n---------------------��ӡ����������ַ------------------\n\n");
	printf("AddressOfFunctions:%x\n",RVAToFOA(FileBuffer,ExportDirectory->AddressOfFunctions));
	printf("AddressOfNames:%x\n",RVAToFOA(FileBuffer,ExportDirectory->AddressOfNames));
	printf("AddressOfNameOrdinals:%x\n",RVAToFOA(FileBuffer,ExportDirectory->AddressOfNameOrdinals));*/
	printf("\n\n---------------------��ӡ������ַ��------------------\n\n");
	DWORD FOA_AddressOfFunctions = RVAToFOA(FileBuffer,ExportDirectory->AddressOfFunctions);
	printf("����������ַ��RVA:%#x\t\t,FOA:%#x\n",ExportDirectory->AddressOfFunctions,FOA_AddressOfFunctions);
	DWORD* AddressFunctions = (DWORD*)(FOA_AddressOfFunctions + (DWORD)FileBuffer);
	for(i = 0;i < ExportDirectory->NumberOfFunctions;i++){
		printf("������ַ[%d]RVA:%#x\t\t������ַ[%d]FOA:%#x\n",i,AddressFunctions[i],i,RVAToFOA(FileBuffer,AddressFunctions[i]));
	}
	printf("\n\n---------------------��ӡ�������Ʊ�------------------\n\n");
	DWORD FOA_AddressOfNames = RVAToFOA(FileBuffer,ExportDirectory->AddressOfNames);
	printf("�����������Ʊ�RVA:%#x\t\t,FOA:%#x\n",ExportDirectory->AddressOfNames,FOA_AddressOfNames);
	DWORD* AddressNames = (DWORD*)(FOA_AddressOfNames + (DWORD)FileBuffer);
	for(i = 0;i < ExportDirectory->NumberOfNames;i++){
		DWORD FOA_AddressNames_Functions = RVAToFOA(FileBuffer,AddressNames[i]);
		char* AddressNames_Name = (char*)(FOA_AddressNames_Functions + (DWORD)FileBuffer);
		printf("���Ʊ�[%d]RVA:%#x\t\t,���Ʊ�[%d]FOA:%#x\t\t,��������:%s\n",i,AddressNames[i],i,FOA_AddressNames_Functions,AddressNames_Name);
	}
	printf("\n\n---------------------��ӡ������ű�------------------\n\n");
	DWORD FOA_AddressOfNameOrdinals = RVAToFOA(FileBuffer,ExportDirectory->AddressOfNameOrdinals);
	printf("������ű�RVA:%#x\t\t,FOA:%#x\n",ExportDirectory->AddressOfNameOrdinals,FOA_AddressOfNameOrdinals);
	WORD* AddressOfNameOrdinals = (WORD*)(FOA_AddressOfNameOrdinals + (DWORD)FileBuffer);
	for(i = 0;i < ExportDirectory->NumberOfNames;i++){
		printf("��ű�[%d]:%#x(%d)\n",i,AddressOfNameOrdinals[i],AddressOfNameOrdinals[i]);
	}
	return 0;
}

//���ú�������ȡ������ַ
int GetFunctionAddrByName(PVOID FileBuffer,const char* Name){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDirectory = NULL;
	DWORD i;
	if(!FileBuffer){
		printf("�ļ���ȡʧ�ܣ�");
		return 0;
	}
	if(*(PWORD)FileBuffer != IMAGE_DOS_SIGNATURE){
		printf("������Ч��MZ!");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*(PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE){
		printf("������Ч��PE�ļ���");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + 20);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	pDirectory = (PIMAGE_DATA_DIRECTORY)((DWORD)pOptionHeader->DataDirectory);
	DWORD pExportDir = RVAToFOA(FileBuffer,pDirectory->VirtualAddress);
	PIMAGE_EXPORT_DIRECTORY pExportFOA = (PIMAGE_EXPORT_DIRECTORY)((DWORD)FileBuffer + pExportDir);
	//���������ֵ�ַ
	DWORD FOA_AddressName = RVAToFOA(FileBuffer,pExportFOA->AddressOfNames);
	DWORD* AddressName = (DWORD*)((DWORD)FileBuffer + FOA_AddressName);
	DWORD ret = -1;
	for(i = 0;i < pExportFOA->NumberOfNames;i++){
		DWORD FOA_AddressName_Fun = RVAToFOA(FileBuffer,AddressName[i]);
		char* AddressN = (char*)(FOA_AddressName_Fun + (DWORD)FileBuffer);
		if(memcmp(Name,(char*)AddressN,strlen(Name)) == 0){
			printf("������RVA:%#x\t\tFOA:%#x\n",pDirectory->VirtualAddress,pExportFOA);
			printf("�ҵ��ˣ�\n���ֱ�[%d]RVA:%#x\t\t,���ֱ�[%d]FOA:%#x\t\t�������֣�%s\n",i,AddressName[i],
				i,RVAToFOA(FileBuffer,AddressName[i]),(char*)AddressN);
			ret = i;
		}
	}
	if(ret == -1){
		printf("δ�ҵ��˺�������");
		return 0;
	}
	DWORD FOA_AddressNameOrdinals = RVAToFOA(FileBuffer,pExportFOA->AddressOfNameOrdinals);
	WORD ret2 = ((WORD*)(FOA_AddressNameOrdinals + (DWORD)FileBuffer))[ret];
	DWORD FOA_AddressFunctions = RVAToFOA(FileBuffer,pExportFOA->AddressOfFunctions);
	DWORD RVA_FunName = ((DWORD*)(FOA_AddressFunctions + (DWORD)FileBuffer))[ret2];
	DWORD FOA_FunName = RVAToFOA(FileBuffer,RVA_FunName);
	printf("�˺�����AddressOrdinals���е��±��ǣ�%d\n",ret);
	printf("�˺�����AddressFunctions���е��±��ǣ�%d\n",ret2);
	printf("�˺���RVA:%#x\t\tFOA:%#x\n",RVA_FunName,FOA_FunName);
	return RVA_FunName + pOptionHeader->ImageBase;
}

//���ú�����Ż�ȡ������ַ
int GetFunctionAddrByOrdinals(PVOID FileBuffer,int Ordinals){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDirectory = NULL;
	if(!FileBuffer){
		printf("�ļ���ȡʧ�ܣ�");
		return 0;
	}
	if(*(PWORD)FileBuffer != IMAGE_DOS_SIGNATURE){
		printf("������Ч��MZ!");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*(PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE){
		printf("������Ч��PE�ļ���");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + 20);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	pDirectory = (PIMAGE_DATA_DIRECTORY)((DWORD)pOptionHeader->DataDirectory);
	DWORD pExportDir = RVAToFOA(FileBuffer,pDirectory->VirtualAddress);
	PIMAGE_EXPORT_DIRECTORY pExportFOA = (PIMAGE_EXPORT_DIRECTORY)((DWORD)FileBuffer + pExportDir);
	int a = Ordinals - pExportFOA->Base;
	DWORD FOA_AddressFunctions = RVAToFOA(FileBuffer,pExportFOA->AddressOfFunctions);
	DWORD RVA_AddressName = ((DWORD*)((DWORD)FileBuffer + FOA_AddressFunctions))[a];
	DWORD FOA_AddressName = RVAToFOA(FileBuffer,RVA_AddressName);
	printf("��ӦRVAΪ:%#x\t\t,FOA:%#x\n",RVA_AddressName,FOA_AddressName);
	return RVA_AddressName + pOptionHeader->ImageBase;
}

//��ӡ�ض�λ��������Ϣ
void PrintBaseRelocation(PVOID FileBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY RVA_pDirectory = NULL;
	if(!FileBuffer){
		printf("�ļ���ȡʧ�ܣ�");
		exit(0);
	}
	if(*(PWORD)FileBuffer != IMAGE_DOS_SIGNATURE){
		printf("������ЧMZ��");
		exit(0);
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*(PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE){
		printf("������ЧPE�ļ���");
		exit(0);
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + 20);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	RVA_pDirectory = (PIMAGE_DATA_DIRECTORY)((DWORD)FileBuffer + pOptionHeader->DataDirectory);
	DWORD FOA_BaseRelocation = RVAToFOA(FileBuffer,pNtHeader->OptionalHeader.DataDirectory[5].VirtualAddress);
	PIMAGE_BASE_RELOCATION BaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)FileBuffer + FOA_BaseRelocation);
	while(BaseRelocation->VirtualAddress != NULL || BaseRelocation->SizeOfBlock != NULL){
		for(DWORD i = 0;i < (BaseRelocation->SizeOfBlock - 8) / 2;i++){
			WORD high4 = *((PWORD)((DWORD)BaseRelocation + 8) + i) >> 12;
			WORD low12 = *((PWORD)((DWORD)BaseRelocation + 8) + i) & 0x0FFF;
			printf("high4:%d\t\tlow:%d\n",high4,low12);
			printf("%d:%d = %x = %x\n",i,high4,BaseRelocation->VirtualAddress + low12,RVAToFOA(FileBuffer,BaseRelocation->VirtualAddress + low12));
		}
		printf("=======================");
		BaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)BaseRelocation + BaseRelocation->SizeOfBlock);
	}
}

//��������
int AddSection(PVOID FileBuffer,DWORD SizeOfFile,DWORD Size,PVOID* NewFileBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	//����ͷ����û�ж����80����
	if((pOptionHeader->SizeOfHeaders - (pDosHeader->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + pFileHeader->SizeOfOptionalHeader + (IMAGE_SIZEOF_SECTION_HEADER * pFileHeader->NumberOfSections))) < 80){
		printf("ʣ��ռ䲻��80��");
		return 0;
	}
	DWORD numSec = pFileHeader->NumberOfSections;
	//���һ���½���
	memcpy((void*)(pSectionHeader + numSec),(void*)(pSectionHeader),sizeof(IMAGE_SECTION_HEADER));
	//�������ں����һ���ڴ�С��0
	memset((void*)(pSectionHeader + numSec + 1),0,sizeof(IMAGE_SECTION_HEADER));
	//�޸Ľ�����
	pFileHeader->NumberOfSections += 1;
	//�޸�SizeOfImage��С
	pOptionHeader->SizeOfImage += Size;
	//����������
	//�޸�����
	BYTE newName[] = {'.','S','o','n','g','\0'};
	memcpy((void*)(pSectionHeader + numSec)->Name,newName,sizeof(newName));
	//�޸�VirtualSize
	(pSectionHeader + numSec)->Misc.VirtualSize = Size;
	//�޸�VirtualAddress
	(pSectionHeader + numSec)->VirtualAddress = (pSectionHeader + numSec - 1)->VirtualAddress + ValueToAlignment((pSectionHeader + numSec - 1)->Misc.VirtualSize,Size);
	//�޸�SizeOfRawData
	(pSectionHeader + numSec)->SizeOfRawData = Size;
	//����PointerToRawData
	(pSectionHeader + numSec)->PointerToRawData = (pSectionHeader + numSec - 1)->PointerToRawData + (pSectionHeader + numSec - 1)->SizeOfRawData;
	*NewFileBuffer = malloc(SizeOfFile + Size);
	memcpy(*NewFileBuffer,FileBuffer,SizeOfFile);
	return (pSectionHeader + numSec)->SizeOfRawData + (pSectionHeader + numSec)->PointerToRawData;
}

//���㵼�����С
int SizeOfExport(PVOID FileBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DWORD i;
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	//���㵼�����ַ
	DWORD FOA_pExport = RVAToFOA(FileBuffer,pOptionHeader->DataDirectory[0].VirtualAddress);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)FileBuffer + FOA_pExport);
	//���㺯�����Ƶ�ַ
	DWORD RVA_AddrName = pExport->AddressOfNames;
	DWORD FOA_AddrName = RVAToFOA(FileBuffer,RVA_AddrName);
	DWORD* AddrName = (DWORD*)((DWORD)FileBuffer + FOA_AddrName);
	//���㵼����Function����
	DWORD SizeOfExport = 4 * pExport->NumberOfFunctions;
	//���㵼����Ordinals����
	SizeOfExport += 2 * pExport->NumberOfNames;
	//���㵼����Names����
	SizeOfExport += 4 * pExport->NumberOfNames;
	//����names��ַ�������ܴ�С
	DWORD NameLen = 0;
	for(i = 0;i < pExport->NumberOfNames;i++){
		DWORD RVA_Names = AddrName[i];
		DWORD FOA_Names = RVAToFOA(FileBuffer,RVA_Names);
		char* Names = (char*)((DWORD)FileBuffer + FOA_Names);
		NameLen += strlen(Names) + 1;
	}
	SizeOfExport += NameLen;
	//���ϵ�����ṹ��С��40
	SizeOfExport += 0x28;
	printf("�������СΪ��%#x(%d)\n",SizeOfExport,SizeOfExport);
	return SizeOfExport;
}

//���������ƶ��������ڱ���
int MoveExportToSection(PVOID FileBuffer,DWORD NewSize){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DWORD i;
	if(!FileBuffer){
		printf("MoveFileΪ�գ�");
		return 0;
	}
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	//���һ���ڱ�
	PIMAGE_SECTION_HEADER LastSection = (PIMAGE_SECTION_HEADER)(pSectionHeader + (pFileHeader->NumberOfSections - 1));
	//���㵼�����ַ
	if(!(pOptionHeader->DataDirectory[0].VirtualAddress)){
		printf("������Ϊ�գ�");
		return 0;
	}
	DWORD FOA_pExport = RVAToFOA(FileBuffer,pOptionHeader->DataDirectory[0].VirtualAddress);
	PIMAGE_EXPORT_DIRECTORY AddrExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)FileBuffer + FOA_pExport);
	//�ƶ�������ַ��
	//������ַ���ַ
	DWORD FOA_AddressOfFunctions = RVAToFOA(FileBuffer,AddrExport->AddressOfFunctions);
	DWORD* AddressOfFunctions = (DWORD*)((DWORD)FileBuffer + FOA_AddressOfFunctions);
	//Ҫ�ƶ����ĵ�ַ
	DWORD* InsertAddrFunction = (DWORD*)((DWORD)FileBuffer + LastSection->PointerToRawData);
	//���������Ʊ�����ݽ��и���
	memcpy(InsertAddrFunction,AddressOfFunctions,4 * AddrExport->NumberOfFunctions);
	//�ƶ�������ű�
	//������ű��ַ
	DWORD FOA_AddressOfOrdinals = RVAToFOA(FileBuffer,AddrExport->AddressOfNameOrdinals);
	WORD* AddressOfOrdinals = (WORD*)((DWORD)FileBuffer + FOA_AddressOfOrdinals);
	//Ҫ�ƶ����ĵ�ַ
	WORD* InsertAddrOrdinals = (WORD*)((DWORD)InsertAddrFunction + 4 * AddrExport->NumberOfFunctions);
	//����Ÿ���
	memcpy(InsertAddrOrdinals,AddressOfOrdinals,2 * AddrExport->NumberOfNames);
	//�ƶ��������Ʊ�
	//�������Ʊ��ַ
	DWORD FOA_AddressOfNames = RVAToFOA(FileBuffer,AddrExport->AddressOfNames);
	DWORD* AddressOfNames = (DWORD*)((DWORD)FileBuffer + FOA_AddressOfNames);
	//Ҫ�ƶ����ĵ�ַ
	DWORD* InsertAddrNames = (DWORD*)((DWORD)InsertAddrOrdinals + 2 * AddrExport->NumberOfNames);
	//�����Ʊ��ַ���ݸ���
	memcpy(InsertAddrNames,AddressOfNames,4 * AddrExport->NumberOfNames);
	//��������Ҫ�ƶ����ĵ�ַ
	char* Addr_Names = (char*)((DWORD)InsertAddrNames + 4 * AddrExport->NumberOfNames);
	//ѭ�������ƴ���
	for(i = 0;i < AddrExport->NumberOfNames;i++){
		//���Ƶ�ַ
		DWORD FOA_Names = RVAToFOA(FileBuffer,AddressOfNames[i]);
		char* Names = (char*)((DWORD)FileBuffer + FOA_Names);
		//�����ַ����Ȳ�����
		DWORD StrLen = strlen(Names);
		memcpy(Addr_Names,Names,StrLen);
		//�޸�RVA��ַ
		Addr_Names[i] = FOAToRVA(FileBuffer,(DWORD)InsertAddrNames - (DWORD)FileBuffer);
		//��ַ+�ַ�����(���µ�ַ
		Addr_Names += StrLen;
		//��\0���벢���µ�ַ
		memcpy(Addr_Names,"\0",1);
		Addr_Names++;
	}
	//���Ƶ�����ṹ
	memcpy(Addr_Names,AddrExport,40);
	//�޸�����
	PIMAGE_EXPORT_DIRECTORY NewExport = (PIMAGE_EXPORT_DIRECTORY)(Addr_Names);
	NewExport->AddressOfFunctions = FOAToRVA(FileBuffer,(DWORD)InsertAddrFunction - (DWORD)FileBuffer);
	NewExport->AddressOfNames = FOAToRVA(FileBuffer,(DWORD)InsertAddrNames - (DWORD)FileBuffer);
	NewExport->AddressOfNameOrdinals = FOAToRVA(FileBuffer,(DWORD)InsertAddrOrdinals - (DWORD)FileBuffer);
	//�޸�Ŀ¼��VirtualAddress
	pOptionHeader->DataDirectory[0].VirtualAddress = FOAToRVA(FileBuffer,(DWORD)NewExport - (DWORD)FileBuffer);
	WriteFilePath(FileBuffer,NewSize,New_File_path);
	return 0;
}

//���ض�λ���ƶ�����������
int MoveRelocationToSec(PVOID FileBuffer,DWORD NewSize){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	//�����ض�λ���ַ
	DWORD FOA_Relocation = RVAToFOA(FileBuffer,pOptionHeader->DataDirectory[5].VirtualAddress);
	PIMAGE_BASE_RELOCATION BaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)FileBuffer + FOA_Relocation);
	//��λ���һ���ڱ��ַ
	PIMAGE_SECTION_HEADER LastSection = (PIMAGE_SECTION_HEADER)(pSectionHeader + (pFileHeader->NumberOfSections - 1));
	//Ҫ��ŵ�Ŀ�ĵ�ַ
	DWORD* LastAddr = (DWORD*)((DWORD)FileBuffer + LastSection->PointerToRawData);
	//�����ض�λ��
	DWORD BaseSize = 0;
	/*for(DWORD i = 0;i != -1;i++){
		if(BaseRelocation->SizeOfBlock !=NULL && BaseRelocation->VirtualAddress != NULL){
			memset(LastAddr,0,8);
			break;
		}
		memcpy(LastAddr,BaseRelocation,8 + BaseRelocation->SizeOfBlock);
		LastAddr += 8 + BaseRelocation->SizeOfBlock;
		BaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)BaseRelocation + BaseRelocation->SizeOfBlock);
	}*/
	while(BaseRelocation->SizeOfBlock != NULL && BaseRelocation->VirtualAddress != NULL){
		BaseSize = BaseSize + BaseRelocation->SizeOfBlock;
		BaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)BaseRelocation + BaseRelocation->SizeOfBlock);
	}
	BaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)FileBuffer + FOA_Relocation);
	memcpy(LastAddr,BaseRelocation,BaseSize);
	//LastAddr += BaseSize;
	//���������DWORD
	//memcpy(LastAddr,0,8);
	//�޸�virtualAddress
	pOptionHeader->DataDirectory[5].VirtualAddress = FOAToRVA(FileBuffer,FOA_Relocation);
	WriteFilePath(FileBuffer,NewSize,New_File_path);
	return 0;
}

//�޸��ض�λ��
int SetRelocation(PVOID FileBuffer,DWORD NewSize,DWORD imageBase){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	//��ȡ�»�ַ��ԭ����ַ�Ĳ�ֵ
	DWORD difference = imageBase - pOptionHeader->ImageBase;
	//��λ��һ���ض�λ��
	DWORD FirstBase = RVAToFOA(FileBuffer,pOptionHeader->DataDirectory[5].VirtualAddress);
	PIMAGE_BASE_RELOCATION BaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)FileBuffer + FirstBase);
	//ѭ�������ض�λ��
	while(BaseRelocation->SizeOfBlock != NULL && BaseRelocation->VirtualAddress != NULL){
		//ѭ������
		for(DWORD i = 0;i < (BaseRelocation->SizeOfBlock - 8) / 2;i++){
			//��4λ
			WORD high4 = *((PWORD)((DWORD)BaseRelocation + 8) + i) >> 12;
			//��12λ
			WORD low12 = *((PWORD)((DWORD)BaseRelocation + 8) + i) & 0xFFF;
			//�ж��Ƿ���Ҫ�޸�
			if(high4 == 3){
				//��ȡ��Ҫ�޸��ĵ�ַ���ļ�PE�е�ƫ��
				DWORD offset = RVAToFOA(FileBuffer,BaseRelocation->VirtualAddress + low12);
				printf("%x = %x = %x = %x\n",offset,BaseRelocation->VirtualAddress + low12,*((PDWORD)((DWORD)FileBuffer + offset)),*((PDWORD)((DWORD)FileBuffer + offset)) + difference);
				//��ַ + ��ֵ
				*((PDWORD)((DWORD)FileBuffer + offset)) += difference;
			}
		}
		BaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)BaseRelocation + BaseRelocation->SizeOfBlock);
	}
	pOptionHeader->ImageBase = imageBase;
	WriteFilePath(FileBuffer,NewSize,New_File_path);
	return 0;
}

int PrintImport(){
	PVOID FileBuffer = NULL;
	ReadFileBuffer(File_path,&FileBuffer);
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	int i, j, k;
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	DWORD RVA_Import = pOptionHeader->DataDirectory[1].VirtualAddress;
	if(!RVA_Import){
		printf("�����Ϊ�գ�");
		return 0;
	}
	DWORD FOA_Import = RVAToFOA(FileBuffer,RVA_Import);
	//���㵼�����ʵ��ַ
	PIMAGE_IMPORT_DESCRIPTOR AddrImport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)FileBuffer + FOA_Import);
	//��ӡ�������Ϣ
	printf("\n\n------------��ӡ�������Ϣ----------\n\n");
	for(i = 0;AddrImport->Characteristics != 0 || AddrImport->FirstThunk != 0 || AddrImport->ForwarderChain != 0 ||
		AddrImport->Name != 0 || AddrImport->OriginalFirstThunk != 0 || AddrImport->TimeDateStamp != 0;i++,AddrImport++){
		//����һ�������ṹ
		printf("----------------������%d��DLL����Ϣ-------------------\n",i + 1);
		//1.��ӡdll������
		char* AddrDllName = (char*)((DWORD)FileBuffer + RVAToFOA(FileBuffer,AddrImport->Name));
		printf("��%d��DLL�����֣�%s\n\n",i + 1,AddrDllName);
		//2.����OriginalFirstThunk(ָ��int��)
		printf("----------------������%d��OriginalFirstThunk(ָ��int��)-----------\n",i + 1);
		DWORD* ThunkData1 = (DWORD*)((DWORD)FileBuffer + RVAToFOA(FileBuffer,AddrImport->OriginalFirstThunk));
		for(j = 0;ThunkData1[j] != 0;j++){
			//�ж����λ�Ƿ�Ϊ1
			if((ThunkData1[j] & 0x80000000) == 0x80000000){
				printf("DLL�����������Ϊ%#x(%d)\n",ThunkData1[j] & 0xfff,ThunkData1[j] & 0xff);//(�����˫�ֽ�)
			}
			if((ThunkData1[j] & 0x80000000) == 0x00000000){
				PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)FileBuffer + RVAToFOA(FileBuffer,ThunkData1[j]));
				printf("Hint:%d\tName:%s\n",ImportByName->Hint,ImportByName->Name);
			}
		}
		//3.����FirstThunk(ָ��iat��)
		printf("\n------------------������%d��FirstThunk---------------\n",i + 1);
		DWORD* ThunkData2 = (DWORD*)((DWORD)FileBuffer + RVAToFOA(FileBuffer,AddrImport->FirstThunk));
		for(k = 0;ThunkData2[k] != 0;k++){
			//�ж�ThunkData2�����λ�Ƿ�Ϊ1
			if((ThunkData2[k] & 0x80000000) == 0x80000000){
				printf("DLL������������ţ�%#x(%d)\n",ThunkData2[k] & 0xfff,ThunkData2[k] & 0xff);
			}
			if((ThunkData2[k] & 0x80000000) == 0x00000000){
				PIMAGE_IMPORT_BY_NAME A_ImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)FileBuffer + RVAToFOA(FileBuffer,ThunkData2[k]));
				printf("Hint:%d\tName:%s\n",A_ImportByName->Hint,A_ImportByName->Name);
			}
		}
		printf("\n\n\n");
	}
	printf("��ӡ�����ɹ���");
	return 0;
}

//��ӡ�����ʱ���
int PrintDataTime(){
	PVOID FileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	ReadFileBuffer(File_path,&FileBuffer);
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	//��λ������ַ
	DWORD FOA_Import = RVAToFOA(FileBuffer,pNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)FileBuffer + FOA_Import);
	for(int i = 0;pImport->Characteristics != 0 || pImport->FirstThunk != 0 || pImport->ForwarderChain != 0 || pImport->Name != 0 ||
		pImport->OriginalFirstThunk != 0 || pImport->TimeDateStamp != 0;i++,pImport++){
		//�����ṹ
		printf("------------------��%d��DLL��Ϣ��--------------------\n",i + 1);
		//��ӡ����
		char* AddrDllName = (char*)((DWORD)FileBuffer + RVAToFOA(FileBuffer,pImport->Name));
		printf("��%d��DLL������Ϊ��%s\n",i + 1,AddrDllName);
		//��ӡʱ���
		printf("ʱ���Ϊ��%x\n\n",pImport->TimeDateStamp);
	}	
	return 0;
}

//��ӡ�󶨵����
int PrintBoundDescr(){
	PVOID FileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	int i;
	ReadFileBuffer(File_path,&FileBuffer);
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	//��λ�󶨵�����ַ
	DWORD FOA_BoundDescr = RVAToFOA(FileBuffer,pNtHeader->OptionalHeader.DataDirectory[11].VirtualAddress);
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundDescr = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)FileBuffer + FOA_BoundDescr);
	DWORD FirstBoundDescr = (DWORD)pBoundDescr;
	//��ӡ�󶨵����ṹ
	for(i = 0;pBoundDescr->OffsetModuleName != 0 || pBoundDescr->TimeDateStamp != 0;i++,pBoundDescr++){
		printf("----------------��%d���󶨵����ṹ------------------\n",i + 1);
		printf("TimeDateStamp:%#x\n",pBoundDescr->TimeDateStamp);
		PBYTE pOffsetModuleName = (PBYTE)(FirstBoundDescr + pBoundDescr->OffsetModuleName);
		printf("OffsetModuleName:%#s\n",pOffsetModuleName);
		printf("NumberOfModuleForwarderRefs:%d\n\n",pBoundDescr->NumberOfModuleForwarderRefs);
		DWORD temp = pBoundDescr->NumberOfModuleForwarderRefs;
		for(int y = 1;y <= pBoundDescr->NumberOfModuleForwarderRefs;y++){
			printf("--------��%d��REF--------\n",y);
			PIMAGE_BOUND_FORWARDER_REF pBoundRef = (PIMAGE_BOUND_FORWARDER_REF)(pBoundDescr + y);
			printf("TimeDateStamp:%x\n",pBoundRef->TimeDateStamp);
			PBYTE pOffsetRef = (PBYTE)(FirstBoundDescr + pBoundRef->OffsetModuleName);
			printf("OffsetModuleName:%s\n\n",pOffsetRef);
		}
	}
	return 0;
}

//��ѯ������
int TestPrintExport(){
	PVOID FileBuffer = NULL;
	ReadFileBuffer(File_path,&FileBuffer);
	PrintExport(FileBuffer);
	return 0;
}

//���ú�������������Ż�ȡ������ַ
int FunctionAddrNaOr(){
	int x;
	PVOID FileBuffer = NULL;
	ReadFileBuffer(File_path,&FileBuffer);
	printf("��ѡ����Ҫ���еĹ��ܣ�\n");
	printf("1.���ú�������ȡ������ַ\n");
	printf("2.���ú�����Ż�ȡ������ַ\n");
	scanf("%d",&x);
	switch(x){
		case 1:
			printf("�Ժ���������Div������ַ��%#x\n",GetFunctionAddrByName(FileBuffer,"Div"));
			getchar();
			break;
		case 2:
			int Ordinals = 3;
			printf("�Ժ��������3������ַ��%#x\n",GetFunctionAddrByOrdinals(FileBuffer,Ordinals));
			getchar();
			break;
	}
	return 0;
}

int TestPrintBaseRelocation(){
	PVOID FileBuffer = NULL;
	ReadFileBuffer(File_path,&FileBuffer);
	PrintBaseRelocation(FileBuffer);
	return 0;
}

//�ƶ���������ת
int MoveExport(){
	PVOID FileBuffer = NULL;
	PVOID NewFileBuffer = NULL;
	DWORD SizeOfFile = 0;
	SizeOfFile = ReadFileBuffer(File_path,&FileBuffer);
	//���е������С����
	size_t Size_Export = SizeOfExport(FileBuffer);
	//���ļ�������Ӧ�������С�Ľ�
	DWORD New_Section = AddSection(FileBuffer,SizeOfFile,0x1000,&NewFileBuffer);
	printf("New_Section��%x\n",New_Section);
	//���������ƶ�����������
	DWORD NewSize = SizeOfFile + 0x1000;
	MoveExportToSection(NewFileBuffer,NewSize);
	return 0;
}

//�ƶ��ض�λ����ת
int MoveRelocation(){
	PVOID FileBuffer = NULL;
	PVOID NewFileBuffer = NULL;
	DWORD SizeOfFile = ReadFileBuffer(File_path,&FileBuffer);
	//���ļ�������
	DWORD New_Section = AddSection(FileBuffer,SizeOfFile,0x2000,&NewFileBuffer);
	printf("�����ں��СΪ:%#x\n",New_Section);
	//���ض�λ���ƶ�����������
	DWORD NewSize = SizeOfFile + 0x2000;
	MoveRelocationToSec(NewFileBuffer,NewSize);
	return 0;
}

//�޸��ض�λ��
int SetBase(){
	PVOID FileBuffer = NULL;
	DWORD NewSize = ReadFileBuffer(File_path,&FileBuffer);
	SetRelocation(FileBuffer,NewSize,0x70000000);
	return 0;
}

int main(int argc, char* argv[])
{
	//Info();
	//����shellcode���
	//TestShellcode();
	//��������
	//AddOneSec();
	//��ѯĿ¼
	//TestPrintDirectory();
	//��ѯ������
	//TestPrintExport();
	//���ú�������������Ż�ȡ������ַ
	//FunctionAddrNaOr();
	//��ӡ�ض�λ��������Ϣ
	//TestPrintBaseRelocation();
	//�ƶ�������
	//MoveExport();
	//�ƶ��ض�λ��
	//MoveRelocation();
	//�޸��ض�λ��
	//SetBase();
	//��ӡ�����
	//PrintImport();
	//��ӡ�����ʱ���
	//PrintDataTime();
	//��ӡ�󶨵����
	PrintBoundDescr();
	getchar();
	return 0;
}

