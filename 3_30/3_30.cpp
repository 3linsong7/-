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

//读文件大小
int ReadFileBuffer(char* file_path,PVOID* FileBuffer){
	FILE* fp;
	unsigned int file_size = NULL;
	LPVOID TempFileBuffer = NULL;
	fp = fopen(file_path,"rb");
	if(!fp){
		printf("文件打开失败！");
		return 0;
	}
	fseek(fp,0,SEEK_END);
	file_size = ftell(fp);
	fseek(fp,0,SEEK_SET);
	if(!file_size){
		printf("文件大小为空！");
		return 0;
	}
	TempFileBuffer = malloc(file_size);
	if(!TempFileBuffer){
		printf("初始化内存失败！");
		return 0;
	}
	size_t n = fread(TempFileBuffer,file_size,1,fp);
	if(!n){
		printf("读取内存失败！");
		return 0;
	}
	*FileBuffer = TempFileBuffer;
	TempFileBuffer = NULL;
	fclose(fp);
	return file_size;
}

//对FileBuffer进行拉伸
DWORD CopyImageBuffer(PVOID FileBuffer,PVOID* ImageBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID TempImageBuffer = NULL;
	int i;
	if(!FileBuffer){
		printf("FileBuffer内存为空！");
		return 0;
	}
	if(*((PWORD)FileBuffer) != IMAGE_DOS_SIGNATURE){
		printf("dos头不为MZ！");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*((PDWORD)((DWORD)FileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
		printf("不是有效的PE文件！");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)FileBuffer + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	//初始化大小
	TempImageBuffer = malloc(pOptionHeader->SizeOfImage);
	if(!TempImageBuffer){
		printf("初始化失败！");
		return 0;
	}
	//进行内存填充
	memset(TempImageBuffer,0,pOptionHeader->SizeOfImage);
	//进行头文件复制
	memcpy(TempImageBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for(i = 0;i < pFileHeader->NumberOfSections;i++,pTempSectionHeader++){
		//进行节文件拉伸复制
		memcpy((void*)((DWORD)TempImageBuffer + pTempSectionHeader->VirtualAddress),(void*)((DWORD)FileBuffer + pTempSectionHeader->PointerToRawData),pTempSectionHeader->SizeOfRawData);
	}
	*ImageBuffer = TempImageBuffer;
	TempImageBuffer = NULL;
	return pOptionHeader->SizeOfImage;
}

//对ImageBuffer大小进行压缩
DWORD CopyNewBuffer(PVOID ImageBuffer,PVOID* NewBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID TempNewBuffer = NULL;
	int i,j;
	if(!ImageBuffer){
		printf("ImageBuffer传入为空！");
		return 0;
	}
	if(*((PWORD)ImageBuffer) != IMAGE_DOS_SIGNATURE){
		printf("不是一个有效MZ！");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)ImageBuffer;
	if(*((PDWORD)((DWORD)ImageBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
		printf("不是一个有效PE！");
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
	//初始化大小
	TempNewBuffer = malloc(New_size);
	//设置内存
	memset(TempNewBuffer,0,New_size);
	//拷贝头文件
	memcpy(TempNewBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for(j = 0;j < pFileHeader->NumberOfSections;j++,pTempSectionHeader++){
		memcpy((void*)((DWORD)TempNewBuffer + pTempSectionHeader->PointerToRawData),(void*)((DWORD)ImageBuffer + pTempSectionHeader->VirtualAddress),pTempSectionHeader->SizeOfRawData);
	}
	*NewBuffer = TempNewBuffer;
	TempNewBuffer = NULL;
	return New_size;
}

//进行写文件
DWORD WriteFilePath(PVOID NewBuffer,size_t New_Size,char* write_file_path){
	FILE *fp;
	fp = fopen(write_file_path,"wb+");
	if(!fp){
		printf("文件打开失败！");
		return 0;
	}
	fwrite(NewBuffer,New_Size,1,fp);
	printf("文件保存成功！");
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
	//进行读文件大小.
	int ret1 = ReadFileBuffer(file_path,&FileBuffer);
	printf("ret1内存大小为%x\n",ret1);
	//进行filebuffer伸展，filebuffer->imagebuffer.
	int ret2 = CopyImageBuffer(FileBuffer,&ImageBuffer);
	printf("ret2内存大小为%x\n",ret2);
	//进行imagebuffer压缩，imagebuffer->newbuffer.
	New_size = CopyNewBuffer(ImageBuffer,&NewBuffer);
	printf("New_size的内存大小为%x\n",New_size);
	//进行文件保存，newbuffer-> xin.exe
	WriteFilePath(NewBuffer,New_size,write_file_path);
	return 0;
}
*/

//头计算
int HeaderSize(PVOID FileBuffer,PIMAGE_DOS_HEADER& pDosHeader,PIMAGE_NT_HEADERS& pNtHeader,PIMAGE_FILE_HEADER& pFileHeader,
			   PIMAGE_OPTIONAL_HEADER& pOptionHeader,PIMAGE_SECTION_HEADER& pSectionHeader){
	if(!FileBuffer){
		printf("文件内存为空！");
		return 0;
	}
	if(*(PWORD)FileBuffer != IMAGE_DOS_SIGNATURE){
		printf("不是有效MZ！");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*(PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE){
		printf("不是有效PE！");
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
		printf("不是有效MZ!");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*(PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE){
		printf("不是有效PE!");
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
	//进行文件读取
	ReadFileBuffer(file_path,&FileBuffer);
	if(!FileBuffer){
		printf("文件读取失败！");
		return 0;
	}
	//进行filebuffer文件拉伸
	CopyImageBuffer(FileBuffer,&ImageBuffer);
	if(!ImageBuffer){
		printf("filebuffer内存拉伸失败！");
		free(FileBuffer);
		return 0;
	}
	if(*((PWORD)ImageBuffer) != IMAGE_DOS_SIGNATURE){
		printf("不为MZ");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)ImageBuffer;
	if(*((PDWORD)((DWORD)ImageBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
		printf("该文件不是有效pe文件！");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	if((pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize) < ShellcodeLen){
		printf("代码空间区不够！");
		free(FileBuffer);
		free(ImageBuffer);
		return 0;
	}
	PBYTE CodeBegin = (PBYTE)((DWORD)ImageBuffer + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
	memcpy(CodeBegin,ShellCode,ShellcodeLen);
	printf("codebegin:%#x\n",CodeBegin);
	//E8修正
	DWORD CALLADDR = (MESSAGEBOXADDR - (pOptionHeader->ImageBase +((DWORD)(CodeBegin + 0xD) - (DWORD)ImageBuffer)));
	printf("CALLADDR:%#x\n",CALLADDR);
	*(PDWORD)(CodeBegin + 0x9) = CALLADDR;
	printf("CodeBegin+0x9:%#x\n",*(PDWORD)(CodeBegin+0x9));
	//E9修正
	DWORD JMPADDR = ((pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - (pOptionHeader->ImageBase + ((DWORD)(CodeBegin + ShellcodeLen) - (DWORD)ImageBuffer)));
	*(PDWORD)(CodeBegin + 0xE) = JMPADDR;
	//修改OEP
	pOptionHeader->AddressOfEntryPoint = (DWORD)CodeBegin - (DWORD)ImageBuffer;
	New_size = CopyNewBuffer(ImageBuffer,&NewBuffer);
	if(!New_size){
		printf("new_size无效！");
		return 0;
	}
	int y = WriteFilePath(NewBuffer,New_size,write_file_path);
	if(!y){
		printf("考盘失败！");
		return 0;
	}
	printf("考盘成功！");
	free(FileBuffer);
	free(ImageBuffer);
	free(NewBuffer);
	return 0;
}

//进行新增节区功能
int AddNewSection(PVOID FileBuffer,DWORD SizeofSection,DWORD file_size,PVOID* NewFileBuffer){
	PIMAGE_DOS_HEADER pDosHeader =NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	if(!FileBuffer){
		printf("文件读取失败！");
		return 0;
	}
	if(*((PWORD)FileBuffer) != IMAGE_DOS_SIGNATURE){
		printf("不为MZ!");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*((PDWORD)((DWORD)FileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
		printf("不是有效的PE文件！");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	//判断是否有80个空位可进行添加。
	if((pOptionHeader->SizeOfHeaders - (pDosHeader->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + pFileHeader->SizeOfOptionalHeader + IMAGE_SIZEOF_SECTION_HEADER * pFileHeader->NumberOfSections)) < 80){
		printf("所剩空间不足80，无法添加节表！");
		return 0;
	}
	DWORD numSec = pFileHeader->NumberOfSections;
	//添加一个新的节
	memcpy((void*)(pSectionHeader + numSec),(void*)(pSectionHeader),sizeof(IMAGE_SECTION_HEADER));
	//在新增节后填充一个节大小的000
	memset((void*)(pSectionHeader + numSec + 1),0,sizeof(IMAGE_SECTION_HEADER));
	//修改PE头节的数量
	pFileHeader->NumberOfSections += 1;
	//修改sizeOfImage大小
	pOptionHeader->SizeOfImage += 0x1000;
	//修正新增节的属性
	//修改节表名字
	char* NewSecName = ".Song";
	memcpy((void*)(pSectionHeader + numSec),NewSecName,sizeof(NewSecName));
	//修改其他属性
	(pSectionHeader + numSec)->Misc.VirtualSize = 0x1000;
	//修改vadd
	(pSectionHeader + numSec)->VirtualAddress = (pSectionHeader + numSec - 1)->VirtualAddress + ValueToAlignment((pSectionHeader + numSec - 1)->Misc.VirtualSize,0x1000);
	//修改sizeofRa
	(pSectionHeader + numSec)->SizeOfRawData = 0x1000;
	//更新PointerToRa
	(pSectionHeader + numSec)->PointerToRawData = (pSectionHeader + numSec - 1)->PointerToRawData + (pSectionHeader + numSec - 1)->SizeOfRawData;
	//在原有数据的最后，新增一个节的数据
	//DWORD NewSize = file_size + SizeofSection;
	//PVOID pNewFileBuffer = malloc(NewSize);
	*NewFileBuffer = malloc(file_size + SizeofSection);
	//memset(pNewFileBuffer,0,NewSize);
	memcpy(*NewFileBuffer,FileBuffer,file_size);
	//*NewFileBuffer = pNewFileBuffer;
	return (pSectionHeader + numSec)->SizeOfRawData + (pSectionHeader + numSec)->PointerToRawData;
}

//进行新增节区注入shellcode
int AddNewSecShell(PVOID NewFileBuffer,DWORD file_size){
	PVOID NewBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	if(*((PWORD)NewFileBuffer) != IMAGE_DOS_SIGNATURE){
		printf("不为MZ!");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)NewFileBuffer;
	if(*((PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
		printf("不是有效的PE!");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + 20);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	DWORD numSec = pFileHeader->NumberOfSections;
	if((pSectionHeader + numSec - 1)->Misc.VirtualSize < ShellcodeLen){
		printf("空间不足shellcode长度！");
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
	printf("SHELLCODE添加成功！\n");
	file_size += 0x1000;
	FILE *fp;
	fp = fopen(New_File_path,"wb");
	if(!fp){
		printf("new_file打开失败！");
		return 0;
	}
	fwrite(NewFileBuffer,file_size,1,fp);
	printf("考盘成功！");
	return 0;
}

//新添节中转站
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

//查询输出字典
int TestPrintDirectory(){
	PVOID FileBuffer = NULL;
	ReadFileBuffer(File_path,&FileBuffer);
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	if(*(PWORD)FileBuffer != IMAGE_DOS_SIGNATURE){
		printf("不是有效MZ！");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*(PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE){
		printf("不是有效PE文件！");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + 20);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_DATA_DIRECTORY pDirectoryAddr = pOptionHeader->DataDirectory;
	printf("导出表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("导入表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("资源表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("异常信息表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("安全证书表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("重定位表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("调试信息表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("版权所以表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("全局指针表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("TLS表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("加载配置表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("绑定导入表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("IAT表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("延迟导入表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("COM信息表地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	printf("保留地址：%#x\t\t大小：%#x\n",pDirectoryAddr->VirtualAddress,pDirectoryAddr->Size);
	pDirectoryAddr++;
	return 0;
}

//打印导出表信息
int PrintExport(PVOID FileBuffer){
	if(!FileBuffer){
		printf("文件读取失败！");
		return 0;
	}
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DWORD i;
	if(*(PWORD)FileBuffer != IMAGE_DOS_SIGNATURE){
		printf("不是有效MZ！");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*(PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE){
		printf("不是有效PE文件！");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + 20);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_DATA_DIRECTORY pDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionHeader->DataDirectory);
	if(!pDirectory->VirtualAddress){
		printf("该程序没有导出表！");
		return 0;
	}
	printf("导出表RVA：%#x\n",pDirectory->VirtualAddress);
	DWORD ExportFOA = RVAToFOA(FileBuffer,pOptionHeader->DataDirectory[0].VirtualAddress); 
	if(ExportFOA){
		printf("导出表FOA：%#x\n",ExportFOA);
	}
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ExportFOA + (DWORD)FileBuffer);
	printf("\n\n---------------------打印导出表结构---------------------\n\n");
	//printf("文件名为：%s\n",ExportDirectory->Name);
	printf("Characteristics:%x\n",ExportDirectory->Characteristics);
	printf("TimeDateStamp:%x\n",ExportDirectory->TimeDateStamp);
	printf("Name:%x\n",ExportDirectory->Name);
	printf("Name:%s\n",((DWORD)FileBuffer + ExportDirectory->Name));
	printf("Base:%x\n",ExportDirectory->Base);
	printf("NumberOfFunctions:%x\n",ExportDirectory->NumberOfFunctions);
	printf("NumberOfNames:%x\n",ExportDirectory->NumberOfNames);
/*	printf("\n\n---------------------打印导出表函数地址------------------\n\n");
	printf("AddressOfFunctions:%x\n",RVAToFOA(FileBuffer,ExportDirectory->AddressOfFunctions));
	printf("AddressOfNames:%x\n",RVAToFOA(FileBuffer,ExportDirectory->AddressOfNames));
	printf("AddressOfNameOrdinals:%x\n",RVAToFOA(FileBuffer,ExportDirectory->AddressOfNameOrdinals));*/
	printf("\n\n---------------------打印函数地址表------------------\n\n");
	DWORD FOA_AddressOfFunctions = RVAToFOA(FileBuffer,ExportDirectory->AddressOfFunctions);
	printf("导出函数地址表RVA:%#x\t\t,FOA:%#x\n",ExportDirectory->AddressOfFunctions,FOA_AddressOfFunctions);
	DWORD* AddressFunctions = (DWORD*)(FOA_AddressOfFunctions + (DWORD)FileBuffer);
	for(i = 0;i < ExportDirectory->NumberOfFunctions;i++){
		printf("函数地址[%d]RVA:%#x\t\t函数地址[%d]FOA:%#x\n",i,AddressFunctions[i],i,RVAToFOA(FileBuffer,AddressFunctions[i]));
	}
	printf("\n\n---------------------打印函数名称表------------------\n\n");
	DWORD FOA_AddressOfNames = RVAToFOA(FileBuffer,ExportDirectory->AddressOfNames);
	printf("导出函数名称表RVA:%#x\t\t,FOA:%#x\n",ExportDirectory->AddressOfNames,FOA_AddressOfNames);
	DWORD* AddressNames = (DWORD*)(FOA_AddressOfNames + (DWORD)FileBuffer);
	for(i = 0;i < ExportDirectory->NumberOfNames;i++){
		DWORD FOA_AddressNames_Functions = RVAToFOA(FileBuffer,AddressNames[i]);
		char* AddressNames_Name = (char*)(FOA_AddressNames_Functions + (DWORD)FileBuffer);
		printf("名称表[%d]RVA:%#x\t\t,名称表[%d]FOA:%#x\t\t,函数名字:%s\n",i,AddressNames[i],i,FOA_AddressNames_Functions,AddressNames_Name);
	}
	printf("\n\n---------------------打印函数序号表------------------\n\n");
	DWORD FOA_AddressOfNameOrdinals = RVAToFOA(FileBuffer,ExportDirectory->AddressOfNameOrdinals);
	printf("函数序号表RVA:%#x\t\t,FOA:%#x\n",ExportDirectory->AddressOfNameOrdinals,FOA_AddressOfNameOrdinals);
	WORD* AddressOfNameOrdinals = (WORD*)(FOA_AddressOfNameOrdinals + (DWORD)FileBuffer);
	for(i = 0;i < ExportDirectory->NumberOfNames;i++){
		printf("序号表[%d]:%#x(%d)\n",i,AddressOfNameOrdinals[i],AddressOfNameOrdinals[i]);
	}
	return 0;
}

//利用函数名获取函数地址
int GetFunctionAddrByName(PVOID FileBuffer,const char* Name){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDirectory = NULL;
	DWORD i;
	if(!FileBuffer){
		printf("文件读取失败！");
		return 0;
	}
	if(*(PWORD)FileBuffer != IMAGE_DOS_SIGNATURE){
		printf("不是有效的MZ!");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*(PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE){
		printf("不是有效的PE文件！");
		return 0;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + 20);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	pDirectory = (PIMAGE_DATA_DIRECTORY)((DWORD)pOptionHeader->DataDirectory);
	DWORD pExportDir = RVAToFOA(FileBuffer,pDirectory->VirtualAddress);
	PIMAGE_EXPORT_DIRECTORY pExportFOA = (PIMAGE_EXPORT_DIRECTORY)((DWORD)FileBuffer + pExportDir);
	//导出表名字地址
	DWORD FOA_AddressName = RVAToFOA(FileBuffer,pExportFOA->AddressOfNames);
	DWORD* AddressName = (DWORD*)((DWORD)FileBuffer + FOA_AddressName);
	DWORD ret = -1;
	for(i = 0;i < pExportFOA->NumberOfNames;i++){
		DWORD FOA_AddressName_Fun = RVAToFOA(FileBuffer,AddressName[i]);
		char* AddressN = (char*)(FOA_AddressName_Fun + (DWORD)FileBuffer);
		if(memcmp(Name,(char*)AddressN,strlen(Name)) == 0){
			printf("导出表RVA:%#x\t\tFOA:%#x\n",pDirectory->VirtualAddress,pExportFOA);
			printf("找到了！\n名字表[%d]RVA:%#x\t\t,名字表[%d]FOA:%#x\t\t函数名字：%s\n",i,AddressName[i],
				i,RVAToFOA(FileBuffer,AddressName[i]),(char*)AddressN);
			ret = i;
		}
	}
	if(ret == -1){
		printf("未找到此函数名！");
		return 0;
	}
	DWORD FOA_AddressNameOrdinals = RVAToFOA(FileBuffer,pExportFOA->AddressOfNameOrdinals);
	WORD ret2 = ((WORD*)(FOA_AddressNameOrdinals + (DWORD)FileBuffer))[ret];
	DWORD FOA_AddressFunctions = RVAToFOA(FileBuffer,pExportFOA->AddressOfFunctions);
	DWORD RVA_FunName = ((DWORD*)(FOA_AddressFunctions + (DWORD)FileBuffer))[ret2];
	DWORD FOA_FunName = RVAToFOA(FileBuffer,RVA_FunName);
	printf("此函数在AddressOrdinals表中的下标是：%d\n",ret);
	printf("此函数在AddressFunctions表中的下标是：%d\n",ret2);
	printf("此函数RVA:%#x\t\tFOA:%#x\n",RVA_FunName,FOA_FunName);
	return RVA_FunName + pOptionHeader->ImageBase;
}

//利用函数序号获取函数地址
int GetFunctionAddrByOrdinals(PVOID FileBuffer,int Ordinals){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDirectory = NULL;
	if(!FileBuffer){
		printf("文件读取失败！");
		return 0;
	}
	if(*(PWORD)FileBuffer != IMAGE_DOS_SIGNATURE){
		printf("不是有效的MZ!");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*(PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE){
		printf("不是有效的PE文件！");
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
	printf("对应RVA为:%#x\t\t,FOA:%#x\n",RVA_AddressName,FOA_AddressName);
	return RVA_AddressName + pOptionHeader->ImageBase;
}

//打印重定位表数据信息
void PrintBaseRelocation(PVOID FileBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY RVA_pDirectory = NULL;
	if(!FileBuffer){
		printf("文件读取失败！");
		exit(0);
	}
	if(*(PWORD)FileBuffer != IMAGE_DOS_SIGNATURE){
		printf("不是有效MZ！");
		exit(0);
	}
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(*(PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE){
		printf("不是有效PE文件！");
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

//新增节区
int AddSection(PVOID FileBuffer,DWORD SizeOfFile,DWORD Size,PVOID* NewFileBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	//计算头部有没有多余的80容量
	if((pOptionHeader->SizeOfHeaders - (pDosHeader->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + pFileHeader->SizeOfOptionalHeader + (IMAGE_SIZEOF_SECTION_HEADER * pFileHeader->NumberOfSections))) < 80){
		printf("剩余空间不足80！");
		return 0;
	}
	DWORD numSec = pFileHeader->NumberOfSections;
	//添加一个新节区
	memcpy((void*)(pSectionHeader + numSec),(void*)(pSectionHeader),sizeof(IMAGE_SECTION_HEADER));
	//在新增节后填充一个节大小的0
	memset((void*)(pSectionHeader + numSec + 1),0,sizeof(IMAGE_SECTION_HEADER));
	//修改节数量
	pFileHeader->NumberOfSections += 1;
	//修改SizeOfImage大小
	pOptionHeader->SizeOfImage += Size;
	//修正节属性
	//修改名字
	BYTE newName[] = {'.','S','o','n','g','\0'};
	memcpy((void*)(pSectionHeader + numSec)->Name,newName,sizeof(newName));
	//修改VirtualSize
	(pSectionHeader + numSec)->Misc.VirtualSize = Size;
	//修改VirtualAddress
	(pSectionHeader + numSec)->VirtualAddress = (pSectionHeader + numSec - 1)->VirtualAddress + ValueToAlignment((pSectionHeader + numSec - 1)->Misc.VirtualSize,Size);
	//修改SizeOfRawData
	(pSectionHeader + numSec)->SizeOfRawData = Size;
	//更新PointerToRawData
	(pSectionHeader + numSec)->PointerToRawData = (pSectionHeader + numSec - 1)->PointerToRawData + (pSectionHeader + numSec - 1)->SizeOfRawData;
	*NewFileBuffer = malloc(SizeOfFile + Size);
	memcpy(*NewFileBuffer,FileBuffer,SizeOfFile);
	return (pSectionHeader + numSec)->SizeOfRawData + (pSectionHeader + numSec)->PointerToRawData;
}

//计算导出表大小
int SizeOfExport(PVOID FileBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DWORD i;
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	//计算导出表地址
	DWORD FOA_pExport = RVAToFOA(FileBuffer,pOptionHeader->DataDirectory[0].VirtualAddress);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)FileBuffer + FOA_pExport);
	//计算函数名称地址
	DWORD RVA_AddrName = pExport->AddressOfNames;
	DWORD FOA_AddrName = RVAToFOA(FileBuffer,RVA_AddrName);
	DWORD* AddrName = (DWORD*)((DWORD)FileBuffer + FOA_AddrName);
	//计算导出表Function数量
	DWORD SizeOfExport = 4 * pExport->NumberOfFunctions;
	//计算导出表Ordinals数量
	SizeOfExport += 2 * pExport->NumberOfNames;
	//计算导出表Names数量
	SizeOfExport += 4 * pExport->NumberOfNames;
	//计算names地址中名称总大小
	DWORD NameLen = 0;
	for(i = 0;i < pExport->NumberOfNames;i++){
		DWORD RVA_Names = AddrName[i];
		DWORD FOA_Names = RVAToFOA(FileBuffer,RVA_Names);
		char* Names = (char*)((DWORD)FileBuffer + FOA_Names);
		NameLen += strlen(Names) + 1;
	}
	SizeOfExport += NameLen;
	//加上导出表结构大小，40
	SizeOfExport += 0x28;
	printf("导出表大小为：%#x(%d)\n",SizeOfExport,SizeOfExport);
	return SizeOfExport;
}

//将导出表移动到新增节表中
int MoveExportToSection(PVOID FileBuffer,DWORD NewSize){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DWORD i;
	if(!FileBuffer){
		printf("MoveFile为空！");
		return 0;
	}
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	//最后一个节表
	PIMAGE_SECTION_HEADER LastSection = (PIMAGE_SECTION_HEADER)(pSectionHeader + (pFileHeader->NumberOfSections - 1));
	//计算导出表地址
	if(!(pOptionHeader->DataDirectory[0].VirtualAddress)){
		printf("导出表为空！");
		return 0;
	}
	DWORD FOA_pExport = RVAToFOA(FileBuffer,pOptionHeader->DataDirectory[0].VirtualAddress);
	PIMAGE_EXPORT_DIRECTORY AddrExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)FileBuffer + FOA_pExport);
	//移动函数地址表
	//函数地址表地址
	DWORD FOA_AddressOfFunctions = RVAToFOA(FileBuffer,AddrExport->AddressOfFunctions);
	DWORD* AddressOfFunctions = (DWORD*)((DWORD)FileBuffer + FOA_AddressOfFunctions);
	//要移动到的地址
	DWORD* InsertAddrFunction = (DWORD*)((DWORD)FileBuffer + LastSection->PointerToRawData);
	//将函数名称表的内容进行复制
	memcpy(InsertAddrFunction,AddressOfFunctions,4 * AddrExport->NumberOfFunctions);
	//移动函数序号表
	//函数序号表地址
	DWORD FOA_AddressOfOrdinals = RVAToFOA(FileBuffer,AddrExport->AddressOfNameOrdinals);
	WORD* AddressOfOrdinals = (WORD*)((DWORD)FileBuffer + FOA_AddressOfOrdinals);
	//要移动到的地址
	WORD* InsertAddrOrdinals = (WORD*)((DWORD)InsertAddrFunction + 4 * AddrExport->NumberOfFunctions);
	//将序号复制
	memcpy(InsertAddrOrdinals,AddressOfOrdinals,2 * AddrExport->NumberOfNames);
	//移动函数名称表
	//函数名称表地址
	DWORD FOA_AddressOfNames = RVAToFOA(FileBuffer,AddrExport->AddressOfNames);
	DWORD* AddressOfNames = (DWORD*)((DWORD)FileBuffer + FOA_AddressOfNames);
	//要移动到的地址
	DWORD* InsertAddrNames = (DWORD*)((DWORD)InsertAddrOrdinals + 2 * AddrExport->NumberOfNames);
	//将名称表地址内容复制
	memcpy(InsertAddrNames,AddressOfNames,4 * AddrExport->NumberOfNames);
	//函数名称要移动到的地址
	char* Addr_Names = (char*)((DWORD)InsertAddrNames + 4 * AddrExport->NumberOfNames);
	//循环将名称存入
	for(i = 0;i < AddrExport->NumberOfNames;i++){
		//名称地址
		DWORD FOA_Names = RVAToFOA(FileBuffer,AddressOfNames[i]);
		char* Names = (char*)((DWORD)FileBuffer + FOA_Names);
		//计算字符长度并复制
		DWORD StrLen = strlen(Names);
		memcpy(Addr_Names,Names,StrLen);
		//修复RVA地址
		Addr_Names[i] = FOAToRVA(FileBuffer,(DWORD)InsertAddrNames - (DWORD)FileBuffer);
		//地址+字符长度(更新地址
		Addr_Names += StrLen;
		//将\0存入并更新地址
		memcpy(Addr_Names,"\0",1);
		Addr_Names++;
	}
	//复制导出表结构
	memcpy(Addr_Names,AddrExport,40);
	//修改属性
	PIMAGE_EXPORT_DIRECTORY NewExport = (PIMAGE_EXPORT_DIRECTORY)(Addr_Names);
	NewExport->AddressOfFunctions = FOAToRVA(FileBuffer,(DWORD)InsertAddrFunction - (DWORD)FileBuffer);
	NewExport->AddressOfNames = FOAToRVA(FileBuffer,(DWORD)InsertAddrNames - (DWORD)FileBuffer);
	NewExport->AddressOfNameOrdinals = FOAToRVA(FileBuffer,(DWORD)InsertAddrOrdinals - (DWORD)FileBuffer);
	//修复目录表VirtualAddress
	pOptionHeader->DataDirectory[0].VirtualAddress = FOAToRVA(FileBuffer,(DWORD)NewExport - (DWORD)FileBuffer);
	WriteFilePath(FileBuffer,NewSize,New_File_path);
	return 0;
}

//将重定位表移动到新增节中
int MoveRelocationToSec(PVOID FileBuffer,DWORD NewSize){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	//计算重定位表地址
	DWORD FOA_Relocation = RVAToFOA(FileBuffer,pOptionHeader->DataDirectory[5].VirtualAddress);
	PIMAGE_BASE_RELOCATION BaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)FileBuffer + FOA_Relocation);
	//定位最后一个节表地址
	PIMAGE_SECTION_HEADER LastSection = (PIMAGE_SECTION_HEADER)(pSectionHeader + (pFileHeader->NumberOfSections - 1));
	//要存放的目的地址
	DWORD* LastAddr = (DWORD*)((DWORD)FileBuffer + LastSection->PointerToRawData);
	//复制重定位表
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
	//最后两个空DWORD
	//memcpy(LastAddr,0,8);
	//修复virtualAddress
	pOptionHeader->DataDirectory[5].VirtualAddress = FOAToRVA(FileBuffer,FOA_Relocation);
	WriteFilePath(FileBuffer,NewSize,New_File_path);
	return 0;
}

//修复重定位表
int SetRelocation(PVOID FileBuffer,DWORD NewSize,DWORD imageBase){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	//获取新基址和原本基址的差值
	DWORD difference = imageBase - pOptionHeader->ImageBase;
	//定位第一张重定位表
	DWORD FirstBase = RVAToFOA(FileBuffer,pOptionHeader->DataDirectory[5].VirtualAddress);
	PIMAGE_BASE_RELOCATION BaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)FileBuffer + FirstBase);
	//循环所有重定位表
	while(BaseRelocation->SizeOfBlock != NULL && BaseRelocation->VirtualAddress != NULL){
		//循环所有
		for(DWORD i = 0;i < (BaseRelocation->SizeOfBlock - 8) / 2;i++){
			//高4位
			WORD high4 = *((PWORD)((DWORD)BaseRelocation + 8) + i) >> 12;
			//低12位
			WORD low12 = *((PWORD)((DWORD)BaseRelocation + 8) + i) & 0xFFF;
			//判断是否需要修复
			if(high4 == 3){
				//获取需要修复的地址在文件PE中的偏移
				DWORD offset = RVAToFOA(FileBuffer,BaseRelocation->VirtualAddress + low12);
				printf("%x = %x = %x = %x\n",offset,BaseRelocation->VirtualAddress + low12,*((PDWORD)((DWORD)FileBuffer + offset)),*((PDWORD)((DWORD)FileBuffer + offset)) + difference);
				//地址 + 差值
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
		printf("导入表为空！");
		return 0;
	}
	DWORD FOA_Import = RVAToFOA(FileBuffer,RVA_Import);
	//计算导入表真实地址
	PIMAGE_IMPORT_DESCRIPTOR AddrImport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)FileBuffer + FOA_Import);
	//打印导入表信息
	printf("\n\n------------打印导入表信息----------\n\n");
	for(i = 0;AddrImport->Characteristics != 0 || AddrImport->FirstThunk != 0 || AddrImport->ForwarderChain != 0 ||
		AddrImport->Name != 0 || AddrImport->OriginalFirstThunk != 0 || AddrImport->TimeDateStamp != 0;i++,AddrImport++){
		//遍历一个导入表结构
		printf("----------------遍历第%d个DLL的信息-------------------\n",i + 1);
		//1.打印dll的名字
		char* AddrDllName = (char*)((DWORD)FileBuffer + RVAToFOA(FileBuffer,AddrImport->Name));
		printf("第%d个DLL的名字：%s\n\n",i + 1,AddrDllName);
		//2.遍历OriginalFirstThunk(指向int表)
		printf("----------------遍历第%d个OriginalFirstThunk(指向int表)-----------\n",i + 1);
		DWORD* ThunkData1 = (DWORD*)((DWORD)FileBuffer + RVAToFOA(FileBuffer,AddrImport->OriginalFirstThunk));
		for(j = 0;ThunkData1[j] != 0;j++){
			//判断最高位是否为1
			if((ThunkData1[j] & 0x80000000) == 0x80000000){
				printf("DLL函数导出序号为%#x(%d)\n",ThunkData1[j] & 0xfff,ThunkData1[j] & 0xff);//(序号是双字节)
			}
			if((ThunkData1[j] & 0x80000000) == 0x00000000){
				PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)FileBuffer + RVAToFOA(FileBuffer,ThunkData1[j]));
				printf("Hint:%d\tName:%s\n",ImportByName->Hint,ImportByName->Name);
			}
		}
		//3.遍历FirstThunk(指向iat表)
		printf("\n------------------遍历第%d个FirstThunk---------------\n",i + 1);
		DWORD* ThunkData2 = (DWORD*)((DWORD)FileBuffer + RVAToFOA(FileBuffer,AddrImport->FirstThunk));
		for(k = 0;ThunkData2[k] != 0;k++){
			//判断ThunkData2的最高位是否为1
			if((ThunkData2[k] & 0x80000000) == 0x80000000){
				printf("DLL函数导出表序号：%#x(%d)\n",ThunkData2[k] & 0xfff,ThunkData2[k] & 0xff);
			}
			if((ThunkData2[k] & 0x80000000) == 0x00000000){
				PIMAGE_IMPORT_BY_NAME A_ImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)FileBuffer + RVAToFOA(FileBuffer,ThunkData2[k]));
				printf("Hint:%d\tName:%s\n",A_ImportByName->Hint,A_ImportByName->Name);
			}
		}
		printf("\n\n\n");
	}
	printf("打印导入表成功！");
	return 0;
}

//打印导入表时间戳
int PrintDataTime(){
	PVOID FileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	ReadFileBuffer(File_path,&FileBuffer);
	HeaderSize(FileBuffer,pDosHeader,pNtHeader,pFileHeader,pOptionHeader,pSectionHeader);
	//定位导入表地址
	DWORD FOA_Import = RVAToFOA(FileBuffer,pNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)FileBuffer + FOA_Import);
	for(int i = 0;pImport->Characteristics != 0 || pImport->FirstThunk != 0 || pImport->ForwarderChain != 0 || pImport->Name != 0 ||
		pImport->OriginalFirstThunk != 0 || pImport->TimeDateStamp != 0;i++,pImport++){
		//遍历结构
		printf("------------------第%d个DLL信息：--------------------\n",i + 1);
		//打印名字
		char* AddrDllName = (char*)((DWORD)FileBuffer + RVAToFOA(FileBuffer,pImport->Name));
		printf("第%d个DLL的名字为：%s\n",i + 1,AddrDllName);
		//打印时间戳
		printf("时间戳为：%x\n\n",pImport->TimeDateStamp);
	}	
	return 0;
}

//打印绑定导入表
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
	//定位绑定导入表地址
	DWORD FOA_BoundDescr = RVAToFOA(FileBuffer,pNtHeader->OptionalHeader.DataDirectory[11].VirtualAddress);
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundDescr = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)FileBuffer + FOA_BoundDescr);
	DWORD FirstBoundDescr = (DWORD)pBoundDescr;
	//打印绑定导入表结构
	for(i = 0;pBoundDescr->OffsetModuleName != 0 || pBoundDescr->TimeDateStamp != 0;i++,pBoundDescr++){
		printf("----------------第%d个绑定导入表结构------------------\n",i + 1);
		printf("TimeDateStamp:%#x\n",pBoundDescr->TimeDateStamp);
		PBYTE pOffsetModuleName = (PBYTE)(FirstBoundDescr + pBoundDescr->OffsetModuleName);
		printf("OffsetModuleName:%#s\n",pOffsetModuleName);
		printf("NumberOfModuleForwarderRefs:%d\n\n",pBoundDescr->NumberOfModuleForwarderRefs);
		DWORD temp = pBoundDescr->NumberOfModuleForwarderRefs;
		for(int y = 1;y <= pBoundDescr->NumberOfModuleForwarderRefs;y++){
			printf("--------第%d个REF--------\n",y);
			PIMAGE_BOUND_FORWARDER_REF pBoundRef = (PIMAGE_BOUND_FORWARDER_REF)(pBoundDescr + y);
			printf("TimeDateStamp:%x\n",pBoundRef->TimeDateStamp);
			PBYTE pOffsetRef = (PBYTE)(FirstBoundDescr + pBoundRef->OffsetModuleName);
			printf("OffsetModuleName:%s\n\n",pOffsetRef);
		}
	}
	return 0;
}

//查询导出表
int TestPrintExport(){
	PVOID FileBuffer = NULL;
	ReadFileBuffer(File_path,&FileBuffer);
	PrintExport(FileBuffer);
	return 0;
}

//利用函数名、函数序号获取函数地址
int FunctionAddrNaOr(){
	int x;
	PVOID FileBuffer = NULL;
	ReadFileBuffer(File_path,&FileBuffer);
	printf("请选择您要进行的功能：\n");
	printf("1.利用函数名获取函数地址\n");
	printf("2.利用函数序号获取函数地址\n");
	scanf("%d",&x);
	switch(x){
		case 1:
			printf("以函数名字找Div函数地址：%#x\n",GetFunctionAddrByName(FileBuffer,"Div"));
			getchar();
			break;
		case 2:
			int Ordinals = 3;
			printf("以函数序号找3函数地址：%#x\n",GetFunctionAddrByOrdinals(FileBuffer,Ordinals));
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

//移动导出表中转
int MoveExport(){
	PVOID FileBuffer = NULL;
	PVOID NewFileBuffer = NULL;
	DWORD SizeOfFile = 0;
	SizeOfFile = ReadFileBuffer(File_path,&FileBuffer);
	//进行导出表大小计算
	size_t Size_Export = SizeOfExport(FileBuffer);
	//对文件新增相应导出表大小的节
	DWORD New_Section = AddSection(FileBuffer,SizeOfFile,0x1000,&NewFileBuffer);
	printf("New_Section：%x\n",New_Section);
	//将导出表移动到新增节中
	DWORD NewSize = SizeOfFile + 0x1000;
	MoveExportToSection(NewFileBuffer,NewSize);
	return 0;
}

//移动重定位表中转
int MoveRelocation(){
	PVOID FileBuffer = NULL;
	PVOID NewFileBuffer = NULL;
	DWORD SizeOfFile = ReadFileBuffer(File_path,&FileBuffer);
	//对文件新增节
	DWORD New_Section = AddSection(FileBuffer,SizeOfFile,0x2000,&NewFileBuffer);
	printf("新增节后大小为:%#x\n",New_Section);
	//将重定位表移动到新增节中
	DWORD NewSize = SizeOfFile + 0x2000;
	MoveRelocationToSec(NewFileBuffer,NewSize);
	return 0;
}

//修复重定位表
int SetBase(){
	PVOID FileBuffer = NULL;
	DWORD NewSize = ReadFileBuffer(File_path,&FileBuffer);
	SetRelocation(FileBuffer,NewSize,0x70000000);
	return 0;
}

int main(int argc, char* argv[])
{
	//Info();
	//进行shellcode填充
	//TestShellcode();
	//新增节区
	//AddOneSec();
	//查询目录
	//TestPrintDirectory();
	//查询导出表
	//TestPrintExport();
	//利用函数名、函数序号获取函数地址
	//FunctionAddrNaOr();
	//打印重定位表数据信息
	//TestPrintBaseRelocation();
	//移动导出表
	//MoveExport();
	//移动重定位表
	//MoveRelocation();
	//修复重定位表
	//SetBase();
	//打印导入表
	//PrintImport();
	//打印导入表时间戳
	//PrintDataTime();
	//打印绑定导入表
	PrintBoundDescr();
	getchar();
	return 0;
}

