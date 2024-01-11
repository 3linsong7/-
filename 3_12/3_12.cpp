// 3_12.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"

//Doc文件头
typedef struct DOC_HEADERS{
	WORD e_magic;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	DWORD e_lfanew;
}PeDoc;

//标准PE头		
typedef struct FILE_HEADERS{
	WORD Machine;	
	WORD NumberOfSections;	
	DWORD TimeDateStamp;	
	DWORD PointerToSymbolTable;	
	DWORD NumberOfSymbols;	
	WORD SizeOfOptionalHeader;
	WORD Characteristics;	
}PeFi;

//可选择PE头
typedef struct OPTIONAL_HEADERS{
	WORD Magic;	
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;	
	DWORD AddressOfEntryPoint;	
	DWORD BaseOfCode;	
	DWORD BaseOfData;
	DWORD ImageBase;	
	DWORD SectionAlignment;	
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;	
	WORD MinorImageVersion;	
	WORD MajorSubsystemVersion;	
	WORD MinorSubsystemVersion;	
	DWORD Win32VersionValue;
	DWORD SizeOfImage;	
	DWORD SizeOfHeaders;
	DWORD CheckSum;	
	WORD Subsystem;	
	WORD DllCharacteristics;
	DWORD SizeOfStackReserve;	
	DWORD SizeOfStackCommit;
	DWORD SizeOfHeapReserve;
	DWORD SizeOfHeapCommit;	
	DWORD LoaderFlags;	
	DWORD NumberOfRvaAndSizes;	
}PeOptional;

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

//地址读取
void ReadPeData(char* PeData,PeDoc*& Doc,PeFi*& File,PeOptional*& Option){
	Doc = (PeDoc*)PeData;
	File = (PeFi*)&PeData[Doc->e_lfanew + 4];
	Option = (PeOptional*)&PeData[Doc->e_lfanew + 24];
}

//Doc头数据输出
void DocPrint(PeDoc* Doc){
	printf("<<<<<DOC>>>>>\n");
	printf("e_magic = %x\n",Doc->e_magic);
	printf("e_cblp = %x\n",Doc->e_cblp);
	printf("e_cp = %x\n",Doc->e_cp);
	printf("e_crlc = %x\n",Doc->e_crlc);
	printf("e_cparhdr = %x\n",Doc->e_cparhdr);
	printf("e_minalloc = %x\n",Doc->e_minalloc);
	printf("e_maxalloc = %x\n",Doc->e_maxalloc);
	printf("e_ss = %x\n",Doc->e_ss);
	printf("e_sp = %x\n",Doc->e_sp);
	printf("e_csum = %x\n",Doc->e_csum);
	printf("e_ip = %x\n",Doc->e_ip);
	printf("e_cs = %x\n",Doc->e_cs);
	printf("e_lfarlc = %x\n",Doc->e_lfarlc);
	printf("e_ovno = %x\n",Doc->e_ovno);
	printf("e_res[0] = %x\n e_res[1] = %x\n e_res[2] = %x\n e_res[3] = %x\n",Doc->e_res[0],Doc->e_res[1],Doc->e_res[2],Doc->e_res[3]);
	printf("e_oemid = %x\n",Doc->e_oemid);
	printf("e_oeminfo = %x\n",Doc->e_oeminfo);
	printf("e_res2[0] = %x\n e_res2[1] = %x\n e_res2[2] = %x\n",Doc->e_res2[0],Doc->e_res2[1],Doc->e_res2[2]);
	printf("e_res2[3] = %x\n e_res2[4] = %x\n e_res2[5] = %x\n",Doc->e_res2[3],Doc->e_res2[4],Doc->e_res2[5]);
	printf("e_res2[6] = %x\n e_res2[7] = %x\n e_res2[8] = %x\n",Doc->e_res2[6],Doc->e_res2[7],Doc->e_res2[8]);
	printf("e_res2[9] = %x\n",Doc->e_res2[9]);
	printf("e_lfanew = %x\n",Doc->e_lfanew);
}

//标准PE头数据输出
void FilePrint(PeFi* File){
	printf("<<<<<FILE PE>>>>>>>\n");
	printf("Machine = %x\n",File->Machine);
	printf("NumberOfSections = %x\n",File->NumberOfSections);
	printf("TimeDateStamp = %x\n",File->TimeDateStamp);
	printf("PointerToSymbolTable = %x\n",File->PointerToSymbolTable);
	printf("NumberOfSymbols = %x\n",File->NumberOfSymbols);
	printf("SizeOfOptionalHeader = %x\n",File->SizeOfOptionalHeader);
	printf("Characteristics = %x\n",File->Characteristics);
}

//可选择PE头数据输出
void OptionalPrint(PeOptional* Option){
	printf("<<<<<OPTIONAL PE>>>>>>>\n");
	printf("Magic = %x\n",Option->Magic);
	printf("MajorLinkerVersion = %x\n",Option->MajorLinkerVersion);
	printf("MinorLinkerVersion = %x\n",Option->MinorLinkerVersion);
	printf("SizeOfCode = %x\n",Option->SizeOfCode);
	printf("SizeOfInitializedData = %x\n",Option->SizeOfInitializedData);
	printf("SizeOfUninitializedData = %x\n",Option->SizeOfUninitializedData);
	printf("AddressOfEntryPoint = %x\n",Option->AddressOfEntryPoint);
	printf("BaseOfCode = %x\n",Option->BaseOfCode);
	printf("BaseOfData = %x\n",Option->BaseOfData);
	printf("ImageBase = %x\n",Option->ImageBase);
	printf("SectionAlignment = %x\n",Option->SectionAlignment);
	printf("FileAlignment = %x\n",Option->FileAlignment);
	printf("MajorOperatingSystemVersion = %x\n",Option->MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion = %x\n",Option->MinorOperatingSystemVersion);
	printf("MajorImageVersion = %x\n",Option->MajorImageVersion);
	printf("MinorImageVersion = %x\n",Option->MinorImageVersion);
	printf("MajorSubsystemVersion = %x\n",Option->MajorSubsystemVersion);
	printf("MinorSubsystemVersion = %x\n",Option->MinorSubsystemVersion);
	printf("Win32VersionValue = %x\n",Option->Win32VersionValue);
	printf("SizeOfImage = %x\n",Option->SizeOfImage);
	printf("SizeOfHeaders = %x\n",Option->SizeOfHeaders);
	printf("CheckSum = %x\n",Option->CheckSum);
	printf("Subsystem = %x\n",Option->Subsystem);
	printf("DllCharacteristics = %x\n",Option->DllCharacteristics);
	printf("SizeOfStackReserve = %x\n",Option->SizeOfStackReserve);
	printf("SizeOfStackCommit = %x\n",Option->SizeOfStackCommit);
	printf("SizeOfHeapReserve = %x\n",Option->SizeOfHeapReserve);
	printf("SizeOfHeapCommit = %x\n",Option->SizeOfHeapCommit);
	printf("LoaderFlags = %x\n",Option->LoaderFlags);
	printf("NumberOfRvaAndSizes = %x\n",Option->NumberOfRvaAndSizes);
}

//中转
void Info(char* PeF){
	char* PeData = ReadPeFile(PeF);
	PeDoc* Doc = {NULL};
	PeFi* File = {NULL};
	PeOptional* Option = {NULL};
	ReadPeData(PeData,Doc,File,Option);
	DocPrint(Doc);
	FilePrint(File);
	OptionalPrint(Option);
}

int main(int argc, char* argv[])
{
	Info("C:/fg/fg.exe");
	return 0;
}

