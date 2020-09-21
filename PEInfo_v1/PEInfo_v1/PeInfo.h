#pragma once
# ifndef _PE_H_
# define _PE_H_

# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# define _CRT_SECURE_NO_WARNINGS
# include <QtCore/QCoreApplication>
# include <qdebug>
# include "string"
# include <IMAGEHLP.H>
# pragma comment(lib, "ImageHlp.lib")


# ifdef __cplusplus
extern "C" {
# endif

	int GetFileLength_info(FILE* pf, DWORD* Length);

	int MyReadFile_info(void** pFileAddress, PCHAR FilePath);

	int MyReadFile_V2_info(void** pFileAddress, PCHAR FilePath);

	int MyWriteFile_info(PVOID pFileAddress, DWORD FileSize, LPSTR FilePath);

	int FOA_TO_RVA_info(PVOID FileAddress, DWORD FOA, PDWORD pRVA);

	int RVA_TO_FOA_info(PVOID FileAddress, DWORD RVA, PDWORD pFOA);

	int checkFile_info(PVOID FileAddress);

# ifdef __cplusplus
}
# endif
# endif

QString Final_Str = "*******************PE INFO*******************\n";

int GetFileLength_info(FILE* pf, DWORD* Length)
{
	int ret = 0;

	fseek(pf, 0, SEEK_END);
	*Length = ftell(pf);
	fseek(pf, 0, SEEK_SET);

	return ret;
}

int MyReadFile_info(void** pFileAddress, PCHAR FilePath)
{
	int ret = 0;
	DWORD Length = 0;
	//打开文件
	FILE* pf = fopen(FilePath, "rb");
	if (pf == NULL)
	{
		ret = -1;
		printf("func ReadFile() Error!\n");
		return ret;
	}

	//获取文件长度
	ret = GetFileLength_info(pf, &Length);
	if (ret != 0 && Length == -1)
	{
		ret = -2;
		printf("func GetFileLength_info() Error!\n");
		return ret;
	}

	//分配空间
	*pFileAddress = (PVOID)malloc(Length);
	if (*pFileAddress == NULL)
	{
		ret = -3;
		printf("func malloc() Error!\n");
		return ret;
	}
	memset(*pFileAddress, 0, Length);

	//读取文件进入内存
	fread(*pFileAddress, Length, 1, pf);

	fclose(pf);
	return ret;
}


int MyReadFile_V2_info(void** pFileAddress, PCHAR FilePath)
{
	int ret = 0;
	DWORD Length = 0;
	//打开文件
	FILE* pf = fopen(FilePath, "rb");
	if (pf == NULL)
	{
		ret = -1;
		printf("func ReadFile() Error!\n");
		return ret;
	}

	//获取文件长度
	ret = GetFileLength_info(pf, &Length);
	if (ret != 0 && Length == -1)
	{
		ret = -2;
		printf("func GetFileLength_info() Error!\n");
		return ret;
	}

	//分配空间
	*pFileAddress = (PVOID)malloc(Length);
	if (*pFileAddress == NULL)
	{
		ret = -3;
		printf("func malloc() Error!\n");
		return ret;
	}
	memset(*pFileAddress, 0, Length);

	//读取文件进入内存
	fread(*pFileAddress, Length, 1, pf);

	fclose(pf);
	return ret;
}

int MyWriteFile_info(PVOID pFileAddress, DWORD FileSize, LPSTR FilePath)
{
	int ret = 0;

	FILE* pf = fopen(FilePath, "wb");
	if (pf == NULL)
	{
		ret = -5;
		printf("func fopen() error :%d!\n", ret);
		return ret;
	}

	fwrite(pFileAddress, FileSize, 1, pf);

	fclose(pf);

	return ret;
}

int FOA_TO_RVA_info(PVOID FileAddress, DWORD FOA, PDWORD pRVA)
{
	int ret = 0;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	//FOA在文件头中 或 SectionAlignment 等于 FileAlignment 时RVA等于FOA
	if (FOA < pOptionalHeader->SizeOfHeaders || pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment)
	{
		*pRVA = FOA;
		return ret;
	}
	//FOA在节区中
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (FOA >= pSectionGroup[i].PointerToRawData && FOA < pSectionGroup[i].PointerToRawData + pSectionGroup[i].SizeOfRawData)
		{
			*pRVA = pSectionGroup[i].VirtualAddress + FOA - pSectionGroup[i].PointerToRawData;
			return ret;
		}
	}
	//没有找到地址
	ret = -4;
	printf("func FOA_TO_RVA_info() Error: %d 地址转换失败！\n", ret);
	return ret;
}

int RVA_TO_FOA_info(PVOID FileAddress, DWORD RVA, PDWORD pFOA)
{
	int ret = 0;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	//RVA在文件头中 或 SectionAlignment 等于 FileAlignment 时RVA等于FOA
	if (RVA < pOptionalHeader->SizeOfHeaders || pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment)
	{
		*pFOA = RVA;
		return ret;
	}
	//RVA在节区中
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (RVA >= pSectionGroup[i].VirtualAddress && RVA < pSectionGroup[i].VirtualAddress + pSectionGroup[i].Misc.VirtualSize)
		{
			*pFOA = pSectionGroup[i].PointerToRawData + RVA - pSectionGroup[i].VirtualAddress;
			return ret;
		}
	}
	//没有找到地址
	ret = -4;
	printf("func RVA_TO_FOA_info() Error: %d 地址转换失败！\n", ret);
	return ret;
}

//int RVA_TO_FOA_64() {};
//int FOA_TO_RVA_64() {};

int checkFile_info(PVOID FileAddress)
{
	int ret = 0;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	//计算PE头位置
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)FileAddress + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("Not a pe file!\n");
		return -1;
	}
	//printf("%02X\n", pDosHeader->e_magic);
	//if (pNTHeader->Signature == 0x4550)
		//printf("okk2\n");
	//printf("%04X\n", pNTHeader->Signature);

	//简单返回32or64
	if (pOptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return 64;
	if (pOptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return 32;
	//0x0100  32 bit word machine. 0x2000   File is a DLL.
	//printf("%02X\n", pOptionalHeader->Magic);

	return ret;
}


/*
	author: ls
*/


/*
1、定位导入表，并打印出导入表中的内容、同时打印出INT表和IAT表
*/

int PrintImportTable_info(PVOID FileAddress)
{
	int ret = 0;
	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2、获取导入表的地址
	DWORD ImportDirectory_RVAAdd = pOptionalHeader->DataDirectory[1].VirtualAddress;
	DWORD ImportDirectory_FOAAdd = 0;
	//	(1)、判断导入表是否存在
	if (ImportDirectory_RVAAdd == 0)
	{
		//printf("ImportDirectory 不存在!\n");
		Final_Str.append("ImportDirectory exists!\n");
		return ret;
	}
	//	(2)、获取导入表的FOA地址
	ret = RVA_TO_FOA_info(FileAddress, ImportDirectory_RVAAdd, &ImportDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA_info() Error!\n");
		return ret;
	}

	//3、指向导入表
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)FileAddress + ImportDirectory_FOAAdd);

	//4、循环打印每一个导入表的信息  重要成员为0时结束循环
	while (ImportDirectory->FirstThunk && ImportDirectory->OriginalFirstThunk)
	{
		//	(1)获取导入文件的名字
		DWORD ImportNameAdd_RVA = ImportDirectory->Name;
		DWORD ImportNameAdd_FOA = 0;
		ret = RVA_TO_FOA_info(FileAddress, ImportNameAdd_RVA, &ImportNameAdd_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA_info() Error!\n");
			return ret;
		}
		PCHAR pImportName = (PCHAR)((DWORD)FileAddress + ImportNameAdd_FOA);
		Final_Str.append(QString("======================== = ImportTable %1 Start============================= \n").arg(pImportName));
		//printf("=========================ImportTable %s Start=============================\n", pImportName);
		Final_Str.append(QString("OriginalFirstThunk RVA:%1\n").arg(ImportDirectory->OriginalFirstThunk, 8, 16));
		//printf("OriginalFirstThunk RVA:%08X\n", ImportDirectory->OriginalFirstThunk);

		//	(2)指向INT表
		DWORD OriginalFirstThunk_RVA = ImportDirectory->OriginalFirstThunk;
		DWORD OriginalFirstThunk_FOA = 0;
		ret = RVA_TO_FOA_info(FileAddress, OriginalFirstThunk_RVA, &OriginalFirstThunk_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA_info() Error!\n");
			return ret;
		}
		PDWORD OriginalFirstThunk_INT = (PDWORD)((DWORD)FileAddress + OriginalFirstThunk_FOA);

		//	(3)循环打印INT表的内容		当内容为0时结束
		while (*OriginalFirstThunk_INT)
		{
			//	(4)进行判断,如果最高位为1则是按序号导入信息,去掉最高位就是函数序号,否则是名字导入
			if ((*OriginalFirstThunk_INT) >> 31)	//最高位是1,序号导入
			{
				//	(5)获取函数序号
				DWORD Original = *OriginalFirstThunk_INT << 1 >> 1;	//去除最高标志位。
				Final_Str.append(QString("import by ordinal: %1 -- %2\n").arg(Original, 8, 16).arg(Original, 8, 10));
				//printf("按序号导入: %08Xh -- %08dd\n", Original, Original);	//16进制 -- 10 进制
			}
			else	//名字导入
			{
				//	(5)获取函数名
				DWORD ImportNameAdd_RAV = *OriginalFirstThunk_INT;
				DWORD ImportNameAdd_FOA = 0;
				ret = RVA_TO_FOA_info(FileAddress, ImportNameAdd_RAV, &ImportNameAdd_FOA);
				if (ret != 0)
				{
					printf("func RVA_TO_FOA_info() Error!\n");
					return ret;
				}
				PIMAGE_IMPORT_BY_NAME ImportName = (PIMAGE_IMPORT_BY_NAME)((DWORD)FileAddress + ImportNameAdd_FOA);
				Final_Str.append(QString("impoort by name[HINT/NAME]: %1 -- %2\n").arg(ImportName->Hint, 2, 16).arg(ImportName->Name));
				//printf("按名字导入[HINT/NAME]: %02X--%s\n", ImportName->Hint, ImportName->Name);
			}

			//	(6)指向下一个地址
			OriginalFirstThunk_INT++;
		}
		Final_Str.append(QString("================================================================\n"));
		//printf("======================== = ImportTable %1 Start============================");
		Final_Str.append(QString("FirstThunk RVA   :%1\n").arg(ImportDirectory->FirstThunk, 8, 16));
		Final_Str.append(QString("TimeDateStamp    :%1\n").arg(ImportDirectory->TimeDateStamp, 8, 16));
		//printf("FirstThunk RVA   :%08X\n", ImportDirectory->FirstThunk);
		//printf("TimeDateStamp    :%08X\n", ImportDirectory->TimeDateStamp);

		//	(2)指向IAT表
		DWORD FirstThunk_RVA = ImportDirectory->FirstThunk;
		DWORD FirstThunk_FOA = 0;
		ret = RVA_TO_FOA_info(FileAddress, FirstThunk_RVA, &FirstThunk_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA_info() Error!\n");
			return ret;
		}
		PDWORD FirstThunk_IAT = (PDWORD)((DWORD)FileAddress + FirstThunk_FOA);

		//	(3)判断IAT表是否被绑定	时间戳 = 0:没有绑定地址	时间戳 = 0xFFFFFFFF:绑定地址	――知识在绑定导入表中
		if (ImportDirectory->TimeDateStamp == 0xFFFFFFFF)
		{
			while (*FirstThunk_IAT)
			{
				Final_Str.append(QString("binded func address: %1\n").arg(*FirstThunk_IAT, 8, 16));
				//printf("绑定函数地址: %08X\n", *FirstThunk_IAT);
				FirstThunk_IAT++;
			}
		}
		else
		{
			//	(4)循环打印IAT表的内容		当内容为0时结束	打印方法和INT表一样
			while (*FirstThunk_IAT)
			{
				//	(5)进行判断,如果最高位为1则是按序号导入信息,去掉最高位就是函数序号,否则是名字导入
				if ((*FirstThunk_IAT) >> 31)	//最高位是1,序号导入
				{
					//	(6)获取函数序号
					DWORD Original = *FirstThunk_IAT << 1 >> 1;	//去除最高标志位。
					Final_Str.append(QString("import by ordinal: %1 -- %2\n").arg(Original, 8, 16).arg(Original, 8, 10));
					//printf("按序号导入: %08Xh -- %08dd\n", Original, Original);	//16进制 -- 10 进制
				}
				else	//名字导入
				{
					//	(7)获取函数名
					DWORD ImportNameAdd_RAV = *FirstThunk_IAT;
					DWORD ImportNameAdd_FOA = 0;
					ret = RVA_TO_FOA_info(FileAddress, ImportNameAdd_RAV, &ImportNameAdd_FOA);
					if (ret != 0)
					{
						printf("func RVA_TO_FOA_info() Error!\n");
						return ret;
					}
					PIMAGE_IMPORT_BY_NAME ImportName = (PIMAGE_IMPORT_BY_NAME)((DWORD)FileAddress + ImportNameAdd_FOA);
					Final_Str.append(QString("import by name[HINT/NAME]: %1 -- %2\n").arg(ImportName->Hint, 2, 16).arg(ImportName->Name));
					//printf("按名字导入[HINT/NAME]: %02X--%s\n", ImportName->Hint, ImportName->Name);
				}

				FirstThunk_IAT++;
			}

		}
		Final_Str.append(QString("=========================ImportTable %1 End  =============================\n").arg(pImportName));
		//printf("=========================ImportTable %s End  =============================\n", pImportName);

		//	(8)指向下一个导入表
		ImportDirectory++;
	}

	return ret;
}

/*
	读64位输入表
*/

int PrintImportTable_64_info(PVOID FileAddress)
{
	int ret = 0;
	//QString tmp = "import";
	//Final_Str.append(tmp);
	PIMAGE_NT_HEADERS64 pNTHeader64;
	PIMAGE_DOS_HEADER pDosHeader;
	pDosHeader = (PIMAGE_DOS_HEADER)FileAddress;
	pNTHeader64 = (PIMAGE_NT_HEADERS64)((DWORD)FileAddress + pDosHeader->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	PIMAGE_THUNK_DATA64 _pThunk = NULL;
	DWORD dwThunk = NULL;
	USHORT Hint;
	if (pNTHeader64->OptionalHeader.DataDirectory[1].VirtualAddress == 0)
	{
		Final_Str.append(QString("no import table!\n"));
		//printf("no import table!");
		return ret;
	}
	ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)ImageRvaToVa((PIMAGE_NT_HEADERS)pNTHeader64, pDosHeader, pNTHeader64->OptionalHeader.DataDirectory[1].VirtualAddress, NULL);
	Final_Str.append(QString("=================== import table start ===================\n"));
	//printf("=================== import table start ===================\n");
	for (; ImportDirectory->Name != NULL;)
	{
		char* szName = (PSTR)ImageRvaToVa((PIMAGE_NT_HEADERS)pNTHeader64, pDosHeader, (ULONG)ImportDirectory->Name, 0);
		Final_Str.append(QString("%1\n").arg(szName));
		//printf("%s\n", szName);
		if (ImportDirectory->OriginalFirstThunk != 0)
		{

			dwThunk = ImportDirectory->OriginalFirstThunk;

			_pThunk = (PIMAGE_THUNK_DATA64)ImageRvaToVa((PIMAGE_NT_HEADERS)pNTHeader64, pDosHeader, (ULONG)ImportDirectory->OriginalFirstThunk, NULL);
		}
		else
		{

			dwThunk = ImportDirectory->FirstThunk;

			_pThunk = (PIMAGE_THUNK_DATA64)ImageRvaToVa((PIMAGE_NT_HEADERS)pNTHeader64, pDosHeader, (ULONG)ImportDirectory->FirstThunk, NULL);
		}
		for (; _pThunk->u1.AddressOfData != NULL;)
		{

			char* szFun = (PSTR)ImageRvaToVa((PIMAGE_NT_HEADERS)pNTHeader64, pDosHeader, (ULONG)(((PIMAGE_IMPORT_BY_NAME)_pThunk->u1.AddressOfData)->Name), 0);
			if (szFun != NULL)
				memcpy(&Hint, szFun - 2, 2);
			else
				Hint = -1;
			Final_Str.append(QString("\t%1\t%2\t%3\n").arg(Hint,4,16).arg(dwThunk,4,16).arg(szFun));
			//printf("\t%0.4x\t%0.8x\t%s\n", Hint, dwThunk, szFun);
			dwThunk += 8;
			_pThunk++;
		}
		ImportDirectory++;
	}
	Final_Str.append(QString("=================== import table end ===================\n"));
	//printf("=================== import table end ===================\n");
	return ret;
}


//打印函数地址表
int PrintFunctionAddressTable_info(PVOID FileAddress, DWORD AddressOfFunctions_RVA, DWORD NumberOfFunctions)
{
	int ret = 0;
	DWORD AddressOfFunctions_FOA = 0;

	//1、RVA --> FOA
	ret = RVA_TO_FOA_info(FileAddress, AddressOfFunctions_RVA, &AddressOfFunctions_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA_info() Error!\n");
		return ret;
	}

	//2、指向函数地址表
	PDWORD FuncAddressTable = (PDWORD)((DWORD)FileAddress + AddressOfFunctions_FOA);

	//2、循环打印函数地址表
	Final_Str.append(QString("=================== Function Address Table Start ===================\n"));
	//printf("=================== 函数地址表 Start ===================\n");
	for (DWORD i = 0; i < NumberOfFunctions; i++)
	{
		DWORD FuncAddress_RVA = FuncAddressTable[i];
		DWORD FuncAddress_FOA = 0;
		ret = RVA_TO_FOA_info(FileAddress, FuncAddress_RVA, &FuncAddress_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA_info() Error!\n");
			return ret;
		}
		Final_Str.append(QString("func address' RVA    : %1  |func address' FOA    : %2  \n").arg(FuncAddress_RVA, 8, 16).arg(FuncAddress_FOA, 8, 16));
			//printf("函数地址RVA    : %08X  |函数地址FOA    : %08X  \n", FuncAddress_RVA, FuncAddress_FOA);
	}
	Final_Str.append(QString("=================== Function Address Table End   ===================\n"));
	// printf("=================== 函数地址表 End   ===================\n\n");
	return ret;
}

//打印函数序号表
int PrintFunctionOrdinalTable_info(PVOID FileAddress, DWORD AddressOfOrdinal_RVA, DWORD NumberOfNames, DWORD Base)
{
	int ret = 0;
	DWORD AddressOfOrdinal_FOA = 0;

	//1、RVA --> FOA
	ret = RVA_TO_FOA_info(FileAddress, AddressOfOrdinal_RVA, &AddressOfOrdinal_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA_info() Error!\n");
		return ret;
	}

	//2、指向函数序号表
	PWORD OrdinalTable = (PWORD)((DWORD)FileAddress + AddressOfOrdinal_FOA);

	//3、循环打印函数序号表
	Final_Str.append(QString("=================== Function Ordinals Table Start ===================\n"));
	//printf("=================== 函数序号表 Start ===================\n");
	for (DWORD i = 0; i < NumberOfNames; i++)
	{
		Final_Str.append(QString("func ordinal  :%1  |Base+Ordinal   :%2\n").arg(OrdinalTable[i], 4, 16).arg(OrdinalTable[i] + Base, 4, 16));
		// printf("函数序号  :%04X  |Base+Ordinal   :%04X\n", OrdinalTable[i], OrdinalTable[i] + Base);
	}
	Final_Str.append(QString("=================== Function Ordinals Table End   ===================\n"));
	// printf("=================== 函数序号表 End   ===================\n\n");
	return ret;
}

//打印函数名字表
int PrintFunctionNameTable_info(PVOID FileAddress, DWORD AddressOfNames_RVA, DWORD NumberOfNames)
{
	int ret = 0;
	DWORD AddressOfNames_FOA = 0;

	//1、RVA --> FOA
	ret = RVA_TO_FOA_info(FileAddress, AddressOfNames_RVA, &AddressOfNames_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA_info() Error!\n");
		return ret;
	}

	//2、指向函数名表
	PDWORD NameTable = (PDWORD)((DWORD)FileAddress + AddressOfNames_FOA);

	//3、循环打印函数序号表
	Final_Str.append(QString("=================== Function Name Table Start ===================\n"));
	// printf("=================== 函数名表 Start ===================\n");
	for (DWORD i = 0; i < NumberOfNames; i++)
	{
		DWORD FuncName_RVA = NameTable[i];
		DWORD FuncName_FOA = 0;
		ret = RVA_TO_FOA_info(FileAddress, FuncName_RVA, &FuncName_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA_info() Error!\n");
			return ret;
		}
		PCHAR FuncName = (PCHAR)((DWORD)FileAddress + FuncName_FOA);
		Final_Str.append(QString("func name  :%1\n").arg(FuncName));
		// printf("函数名  :%s\n", FuncName);
	}
	Final_Str.append(QString("=================== Function Name Table End   ===================\n"));
	// printf("=================== 函数名表 End   ===================\n\n");

	return ret;
}

/*
	输出表
*/

int PrintExportTable_info(PVOID FileAddress)
{
	int ret = 0;

	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	//printf("%02X\n", pOptionalHeader->Magic);
	//2、获取导出表的地址
	DWORD ExportDirectory_RAVAdd = pOptionalHeader->DataDirectory[0].VirtualAddress;
	DWORD ExportDirectory_FOAAdd = 0;
	//	(1)、判断导出表是否存在
	if (ExportDirectory_RAVAdd == 0)
	{
		Final_Str.append(QString("ExportTable not exists!\n"));
		// printf("ExportDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取导出表的FOA地址
	ret = RVA_TO_FOA_info(FileAddress, ExportDirectory_RAVAdd, &ExportDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA_info() Error!\n");
		return ret;
	}

	//3、指向导出表
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)FileAddress + ExportDirectory_FOAAdd);

	//4、找到文件名
	DWORD FileName_RVA = ExportDirectory->Name;
	DWORD FileName_FOA = 0;
	ret = RVA_TO_FOA_info(FileAddress, FileName_RVA, &FileName_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA_info() Error!\n");
		return ret;
	}
	PCHAR FileName = (PCHAR)((DWORD)FileAddress + FileName_FOA);

	//5、打印导出表信息
	Final_Str.append(QString("*********************************************************\n=======================ExportTable=======================\n"));
	Final_Str.append(QString("DWORD Characteristics;        :  %1\n").arg(ExportDirectory->Characteristics, 8, 16));
	Final_Str.append(QString("DWORD TimeDateStamp;        	:  %1\n").arg(ExportDirectory->TimeDateStamp, 8, 16));
	Final_Str.append(QString("DWORD MajorVersion;        	:  %1\n").arg(ExportDirectory->MajorVersion, 4, 16));
	Final_Str.append(QString("DWORD Name;        			:  %1\n").arg(ExportDirectory->Name, 4, 16));
	Final_Str.append(QString("DWORD Base;        			:  %1\n").arg(ExportDirectory->Base, 8, 16));
	Final_Str.append(QString("DWORD NumberOfFunctions;      :  %1\n").arg(ExportDirectory->NumberOfFunctions, 8, 16));
	Final_Str.append(QString("DWORD NumberOfNames;        	:  %1\n").arg(ExportDirectory->NumberOfNames, 8, 16));
	Final_Str.append(QString("DWORD AddressOfFunctions;     :  %1\n").arg(ExportDirectory->AddressOfFunctions, 8, 16));
	Final_Str.append(QString("DWORD AddressOfNames;        	:  %1\n").arg(ExportDirectory->AddressOfNames, 8, 16));
	Final_Str.append(QString("DWORD AddressOfNameOrdinals;  :  %1\n").arg(ExportDirectory->AddressOfNameOrdinals, 8, 16));
	// printf("*********************************************************\n");
	// printf("=======================ExportTable=======================\n");
	// printf("DWORD Characteristics;        :  %08X\n", ExportDirectory->Characteristics);
	// printf("DWORD TimeDateStamp;          :  %08X\n", ExportDirectory->TimeDateStamp);
	// printf("WORD  MajorVersion;           :  %04X\n", ExportDirectory->MajorVersion);
	// printf("WORD  MinorVersion;           :  %04X\n", ExportDirectory->MinorVersion);
	// printf("DWORD Name;                   :  %08X     \"%s\"\n", ExportDirectory->Name, FileName);
	// printf("DWORD Base;                   :  %08X\n", ExportDirectory->Base);
	// printf("DWORD NumberOfFunctions;      :  %08X\n", ExportDirectory->NumberOfFunctions);
	// printf("DWORD NumberOfNames;          :  %08X\n", ExportDirectory->NumberOfNames);
	// printf("DWORD AddressOfFunctions;     :  %08X\n", ExportDirectory->AddressOfFunctions);
	// printf("DWORD AddressOfNames;         :  %08X\n", ExportDirectory->AddressOfNames);
	// printf("DWORD AddressOfNameOrdinals;  :  %08X\n", ExportDirectory->AddressOfNameOrdinals);
	Final_Str.append(QString("=========================================================\n*********************************************************\n"));

	// printf("=========================================================\n");
	// printf("*********************************************************\n");

	//6、打印函数地址表 数量由NumberOfFunctions决定
	ret = PrintFunctionAddressTable_info(FileAddress, ExportDirectory->AddressOfFunctions, ExportDirectory->NumberOfFunctions);
	if (ret != 0)
	{
		printf("func PrintFunctionAddressTable_info() Error!\n");
		return ret;
	}

	//7、打印函数序号表 数量由NumberOfNames决定
	ret = PrintFunctionOrdinalTable_info(FileAddress, ExportDirectory->AddressOfNameOrdinals, ExportDirectory->NumberOfNames, ExportDirectory->Base);
	if (ret != 0)
	{
		printf("func PrintFunctionOrdinalTable_info() Error!\n");
		return ret;
	}

	//8、打印函数名表 数量由NumberOfNames决定
	ret = PrintFunctionNameTable_info(FileAddress, ExportDirectory->AddressOfNames, ExportDirectory->NumberOfNames);
	if (ret != 0)
	{
		printf("func PrintFunctionNameTable_info() Error!\n");
		return ret;
	}

	return ret;
}

int PrintExportTable_64_info(PVOID FileAddress)
{
	int ret = 0;
	QString tmp = "export";
	Final_Str.append(tmp);
	//1.指向相关内容
	PIMAGE_NT_HEADERS64 pNTHeader64;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	pDosHeader = (PIMAGE_DOS_HEADER)FileAddress;
	pNTHeader64 = (PIMAGE_NT_HEADERS64)((DWORD)FileAddress + pDosHeader->e_lfanew);

	if (pNTHeader64->OptionalHeader.DataDirectory[0].VirtualAddress == 0)
	{
		Final_Str.append(QString("ExportTable not exists!\n"));
		return ret;
	}
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)ImageRvaToVa((PIMAGE_NT_HEADERS)pNTHeader64, pDosHeader, pNTHeader64->OptionalHeader.DataDirectory[0].VirtualAddress, NULL);
	DWORD i = 0;
	DWORD NumberOfNames = pExportDirectory->NumberOfNames;
	//printf("%d\n", NumberOfNames);
	//printf("%d\n", pExportDirectory->NumberOfFunctions);
	//DWORD NumberOF
	ULONGLONG** NameTable = (ULONGLONG**)pExportDirectory->AddressOfNames;
	NameTable = (PULONGLONG*)ImageRvaToVa((PIMAGE_NT_HEADERS)pNTHeader64, pDosHeader, (ULONG)NameTable, NULL);

	ULONGLONG** AddressTable = (ULONGLONG**)pExportDirectory->AddressOfFunctions;
	AddressTable = (PULONGLONG*)ImageRvaToVa((PIMAGE_NT_HEADERS)pNTHeader64, pDosHeader, (DWORD)AddressTable, NULL);

	ULONGLONG** OrdinalTable = (ULONGLONG**)ImageRvaToVa((PIMAGE_NT_HEADERS)pNTHeader64, pDosHeader, (ULONG)pExportDirectory->AddressOfNameOrdinals, NULL);
	//OrdinalTable = (PULONGLONG*)ImageRvaToVa((PIMAGE_NT_HEADERS)pNTHeader64, pDosHeader, (DWORD)OrdinalTable, NULL);
	//PIMAGE_IMPORT_BY_NAME;

	char* szFun = (PSTR)ImageRvaToVa((PIMAGE_NT_HEADERS)pNTHeader64, pDosHeader, (ULONG)*NameTable, NULL);
	Final_Str.append(QString("=================== export table start ===================\n"));
	//printf("=================== export table start ===================\n");
	char tmps1[100];

	char tmps2[100];
	for (i = 0; i < NumberOfNames; i++)
	{
		itoa(i, tmps1, 10);
		itoa(**AddressTable, tmps2, 10);
		Final_Str.append(QString("%1\t%2\t%3\n").arg(tmps1, 4, 16).arg(tmps2, 8, 16).arg(szFun));
		//printf("%0.4x\t%0.8x\t%s\n", i + pExportDirectory->Base, *AddressTable, szFun);
		//printf("%s\n", szFun);
		szFun = szFun + strlen(szFun) + 1;
		AddressTable++;
		/*if (i % 200 == 0 && i / 200 >= 1)
		{
			printf("{Press [ENTER] to continue...}");
			getchar();
		}*/
	}
	Final_Str.append(QString("=================== export table end ===================\n"));
	//printf("=================== export table end ===================\n");
	return ret;
}

/*
	重定位表
*/
int PrintReloactionTable_info(PVOID FileAddress)
{
	int ret = 0;

	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2、获取重定位表的地址
	DWORD RelocationDirectory_RAVAdd = pOptionalHeader->DataDirectory[5].VirtualAddress;
	DWORD RelocationDirectory_FOAAdd = 0;
	//	(1)、判断重定位表是否存在
	if (RelocationDirectory_RAVAdd == 0)
	{
		Final_Str.append(QString("RelocationDirectory not exists!\n"));
		// printf("RelocationDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取重定位表的FOA地址
	ret = RVA_TO_FOA_info(FileAddress, RelocationDirectory_RAVAdd, &RelocationDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA_info() Error!\n");
		return ret;
	}

	//3、指向重定位表
	PIMAGE_BASE_RELOCATION RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)FileAddress + RelocationDirectory_FOAAdd);

	//4、循环打印重定位信息  当VirtualAddress和SizeOfBlock都为0时遍历完成
	while (RelocationDirectory->VirtualAddress && RelocationDirectory->SizeOfBlock)
	{
		Final_Str.append(QString("VirtualAddress    :%1\n").arg(RelocationDirectory->VirtualAddress, 8, 16));
		Final_Str.append(QString("SizeOfBlock    :%1\n").arg(RelocationDirectory->SizeOfBlock, 8, 16));
		// printf("VirtualAddress    :%08X\n", RelocationDirectory->VirtualAddress);
		// printf("SizeOfBlock       :%08X\n", RelocationDirectory->SizeOfBlock);
		Final_Str.append(QString("================= BlockData Start ======================\n"));
		// printf("================= BlockData Start ======================\n");
		//5、计算在当前块中的数据个数
		DWORD DataNumber = (RelocationDirectory->SizeOfBlock - 8) / 2;

		//6、指向数据块
		PWORD DataGroup = (PWORD)((DWORD)RelocationDirectory + 8);

		//7、循环打印数据块中的数据
		for (DWORD i = 0; i < DataNumber; i++)
		{
			//(1)判断高4位是否为0
			if (DataGroup[i] >> 12 != 0)
			{
				//(2)提取数据块中的有效数据 低12位
				WORD BlockData = DataGroup[i] & 0xFFF;

				//(3)计算数据块的RVA和FOA
				DWORD Data_RVA = RelocationDirectory->VirtualAddress + BlockData;
				DWORD Data_FOA = 0;
				ret = RVA_TO_FOA_info(FileAddress, Data_RVA, &Data_FOA);
				if (ret != 0)
				{
					printf("func RVA_TO_FOA_info() Error!\n");
					return ret;
				}
				//(4)获取需要重定位的数据
				PDWORD RelocationData = (PDWORD)((DWORD)FileAddress + Data_FOA);
				Final_Str.append(QString("[%1]    |data :[%2]   |data's RVA :[%3]  |data's attributes :[%4]  |relocation data  :[%5]\n").arg(i + 1, 4, 16).arg(BlockData, 4, 16).arg(Data_RVA, 8, 16).arg((DataGroup[i] >> 12), 1, 16).arg(*RelocationData, 8, 16));

				//printf("第[%04X]项    |数据 :[%04X]   |数据的RVA :[%08X]  |数据属性 :[%X]  |重定位数据  :[%08X]\n", i + 1, BlockData, Data_RVA, (DataGroup[i] >> 12), *RelocationData);
			}
		}
		Final_Str.append(QString("================= BlockData End ========================\n"));
		// printf("================= BlockData End ========================\n");

		//指向下一个数据块
		RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)RelocationDirectory + RelocationDirectory->SizeOfBlock);
	}
	return ret;
}

int PrintReloactionTable_64_info(PVOID FileAddress)
{
	int ret = 0;

	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2、获取重定位表的地址
	DWORD RelocationDirectory_RAVAdd = pOptionalHeader->DataDirectory[5].VirtualAddress;
	DWORD RelocationDirectory_FOAAdd = 0;
	//	(1)、判断重定位表是否存在
	if (RelocationDirectory_RAVAdd == 0)
	{
		Final_Str.append(QString("RelocationDirectory not exists!\n"));
		// printf("RelocationDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取重定位表的FOA地址
	ret = RVA_TO_FOA_info(FileAddress, RelocationDirectory_RAVAdd, &RelocationDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA_info() Error!\n");
		return ret;
	}

	//3、指向重定位表
	PIMAGE_BASE_RELOCATION RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)FileAddress + RelocationDirectory_FOAAdd);

	//4、循环打印重定位信息  当VirtualAddress和SizeOfBlock都为0时遍历完成
	while (RelocationDirectory->VirtualAddress && RelocationDirectory->SizeOfBlock)
	{
		Final_Str.append(QString("VirtualAddress    :%1\n").arg(RelocationDirectory->VirtualAddress, 8, 16));
		Final_Str.append(QString("SizeOfBlock    :%1\n").arg(RelocationDirectory->SizeOfBlock, 8, 16));
		// printf("VirtualAddress    :%08X\n", RelocationDirectory->VirtualAddress);
		// printf("SizeOfBlock       :%08X\n", RelocationDirectory->SizeOfBlock);
		Final_Str.append(QString("================= BlockData Start ======================\n"));
		// printf("================= BlockData Start ======================\n");
		//5、计算在当前块中的数据个数
		DWORD DataNumber = (RelocationDirectory->SizeOfBlock - 8) / 2;

		//6、指向数据块
		PWORD DataGroup = (PWORD)((DWORD)RelocationDirectory + 8);

		//7、循环打印数据块中的数据
		for (DWORD i = 0; i < DataNumber; i++)
		{
			//(1)判断高4位是否为0
			if (DataGroup[i] >> 12 != 0)
			{
				//(2)提取数据块中的有效数据 低12位
				WORD BlockData = DataGroup[i] & 0xFFF;

				//(3)计算数据块的RVA和FOA
				DWORD Data_RVA = RelocationDirectory->VirtualAddress + BlockData;
				DWORD Data_FOA = 0;
				ret = RVA_TO_FOA_info(FileAddress, Data_RVA, &Data_FOA);
				if (ret != 0)
				{
					printf("func RVA_TO_FOA_info() Error!\n");
					return ret;
				}
				//(4)获取需要重定位的数据
				PDWORD RelocationData = (PDWORD)((DWORD)FileAddress + Data_FOA);

				//printf("第[%04X]项    |数据 :[%04X]   |数据的RVA :[%08X]  |数据属性 :[%X]  |重定位数据  :[%08X]\n", i + 1, BlockData, Data_RVA, (DataGroup[i] >> 12), *RelocationData);
				Final_Str.append(QString("[%1]    |data :[%2]   |data's RVA :[%3]  |data's attributes  :[%4]  |relocation data  :[%5]\n").arg(i + 1, 4, 16).arg(BlockData, 4, 16).arg(Data_RVA, 8, 16).arg((DataGroup[i] >> 12), 1, 16).arg(*RelocationData, 8, 16));
			}
		}
		Final_Str.append(QString("================= BlockData End ========================\n"));
		// printf("================= BlockData End ========================\n");

		//指向下一个数据块
		RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)RelocationDirectory + RelocationDirectory->SizeOfBlock);
	}
	return ret;
}

/*
	资源表
*/
int PrintResourceTable_info(PVOID FileAddress)
{
	/*string szResType[0x11] = { 0, "鼠标指针", "位图", "图标", "菜单",
						 "对话框", "字符串列表", "字体目录", "字体",
						 "加速键", "非格式化资源", "消息列表", "鼠标指针组",
						 "zz", "图标组", "xx", "版本信息" };
	*/
	int szResType[17] = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
		'9', '10', '11', '12', '13', '14', '15', '16' };

	int ret = 0;
	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2、获取资源表的地址
	DWORD ResourceDirectory_RVAAdd = pOptionalHeader->DataDirectory[2].VirtualAddress;
	DWORD ResourceDirectory_FOAAdd = 0;
	//	(1)、判断资源表是否存在
	if (ResourceDirectory_RVAAdd == 0)
	{
		Final_Str.append(QString("ResourceDirectory not exists!\n"));
		// printf("ResourceDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取资源表的FOA地址
	ret = RVA_TO_FOA_info(FileAddress, ResourceDirectory_RVAAdd, &ResourceDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA_info() Error!\n");
		return ret;
	}

	//3、指向资源表
	PIMAGE_RESOURCE_DIRECTORY ResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)FileAddress + ResourceDirectory_FOAAdd);

	//4、打印资源表信息(一级目录)
	Final_Str.append(QString("|==================================================\n"));
	// printf("|==================================================\n");
	Final_Str.append(QString("|resources table 1st index:\n"));
	// printf("|资源表一级目录信息:\n");
	Final_Str.append(QString("|Characteristics        	:%1\n").arg(ResourceDirectory->Characteristics, 8, 16));
	Final_Str.append(QString("|TimeDateStamp        	:%1\n").arg(ResourceDirectory->TimeDateStamp, 8, 16));
	Final_Str.append(QString("|MajorVersion        		:%1\n").arg(ResourceDirectory->MajorVersion, 4, 16));
	Final_Str.append(QString("|MinorVersion        		:%1\n").arg(ResourceDirectory->MinorVersion, 4, 16));
	Final_Str.append(QString("|NumberOfNamedEntries     :%1\n").arg(ResourceDirectory->NumberOfNamedEntries, 4, 16));
	Final_Str.append(QString("|NumberOfIdEntries        :%1\n").arg(ResourceDirectory->NumberOfIdEntries, 4, 16));
	// printf("|Characteristics        :%08X\n", ResourceDirectory->Characteristics);
	// printf("|TimeDateStamp          :%08X\n", ResourceDirectory->TimeDateStamp);
	// printf("|MajorVersion           :%04X\n", ResourceDirectory->MajorVersion);
	// printf("|MinorVersion           :%04X\n", ResourceDirectory->MinorVersion);
	// printf("|NumberOfNamedEntries   :%04X\n", ResourceDirectory->NumberOfNamedEntries);
	// printf("|NumberOfIdEntries      :%04X\n", ResourceDirectory->NumberOfIdEntries);
	Final_Str.append(QString("|==================================================\n"));
	// printf("|==================================================\n");

	//4、循环打印后续资源表信息
	//	(1)指向一级目录中的资源目录项(一级目录)	资源类型
	PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirectoryEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)ResourceDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY));

	Final_Str.append(QString("|----------------------------------------\n"));
	// printf("|----------------------------------------\n");

	for (int i = 0; i < (ResourceDirectory->NumberOfIdEntries + ResourceDirectory->NumberOfNamedEntries); i++)
	{
		//	(2)判断一级目录中的资源目录项中类型是否是字符串 1 = 字符串(非标准类型)； 0 = 非字符串(标准类型)
		if (ResourceDirectoryEntry->NameIsString) //字符串(非标准类型)
		{
			//		1.指向名字结构体
			PIMAGE_RESOURCE_DIR_STRING_U pStringName = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)ResourceDirectory + ResourceDirectoryEntry->NameOffset);

			//		2.将Unicode字符串转换成ASCII字符串
			CHAR TypeName[20] = { 0 };
			for (int j = 0; j < pStringName->Length; j++)
			{
				TypeName[j] = (CHAR)pStringName->NameString[j];
			}
			//		3.打印字符串
			Final_Str.append(QString("|ResourceType           :\"%1\"\n").arg(TypeName));
			// printf("|ResourceType           :\"%s\"\n", TypeName);
		}
		else //非字符串(标准类型)
		{
			if (ResourceDirectoryEntry->Id < 0x11) //只有1 - 16有定义
				Final_Str.append(QString("|ResourceType           :\"%1\"\n").arg(szResType[ResourceDirectoryEntry->Id]));
			//printf("|ResourceType           :%d\n", szResType[ResourceDirectoryEntry->Id]);
			else
				Final_Str.append(QString("|ResourceType           :\"%1\"\n").arg(ResourceDirectoryEntry->Id, 4, 16));
			// printf("|ResourceType           :%04Xh\n", ResourceDirectoryEntry->Id);
		}

		//	(3)判断一级目录中子节点的类型		1 = 目录； 0 = 数据 (一级目录和二级目录该值都为1)
		if (ResourceDirectoryEntry->DataIsDirectory)
		{
			//	(4)打印目录偏移
			Final_Str.append(QString("|OffsetToDirectory      :%1\n").arg(ResourceDirectoryEntry->OffsetToDirectory, 8, 16));
			//printf("|OffsetToDirectory      :%08X\n", ResourceDirectoryEntry->OffsetToDirectory);
			Final_Str.append(QString("|----------------------------------------\n"));
			//printf("|----------------------------------------\n");

			//	(5)指向二级目录	资源编号
			PIMAGE_RESOURCE_DIRECTORY ResourceDirectory_Sec = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)ResourceDirectory + ResourceDirectoryEntry->OffsetToDirectory);

			//	(6)打印资源表信息(二级目录)
			//printf("    |====================================\n");
			Final_Str.append(QString("|==================================================\n"));
			Final_Str.append(QString("|resources table 2nd index:\n"));
			// printf("|资源表一级目录信息:\n");
			Final_Str.append(QString("|Characteristics        	:%1\n").arg(ResourceDirectory_Sec->Characteristics, 8, 16));
			Final_Str.append(QString("|TimeDateStamp        	:%1\n").arg(ResourceDirectory_Sec->TimeDateStamp, 8, 16));
			Final_Str.append(QString("|MajorVersion        		:%1\n").arg(ResourceDirectory_Sec->MajorVersion, 4, 16));
			Final_Str.append(QString("|MinorVersion        		:%1\n").arg(ResourceDirectory_Sec->MinorVersion, 4, 16));
			Final_Str.append(QString("|NumberOfNamedEntries     :%1\n").arg(ResourceDirectory_Sec->NumberOfNamedEntries, 4, 16));
			Final_Str.append(QString("|NumberOfIdEntries        :%1\n").arg(ResourceDirectory_Sec->NumberOfIdEntries, 4, 16));
			// printf("    |资源表二级目录信息:\n");
			// printf("    |Characteristics        :%08X\n", ResourceDirectory_Sec->Characteristics);
			// printf("    |TimeDateStamp          :%08X\n", ResourceDirectory_Sec->TimeDateStamp);
			// printf("    |MajorVersion           :%04X\n", ResourceDirectory_Sec->MajorVersion);
			// printf("    |MinorVersion           :%04X\n", ResourceDirectory_Sec->MinorVersion);
			// printf("    |NumberOfNamedEntries   :%04X\n", ResourceDirectory_Sec->NumberOfNamedEntries);
			// printf("    |NumberOfIdEntries      :%04X\n", ResourceDirectory_Sec->NumberOfIdEntries);
			//printf("    |====================================\n");
			Final_Str.append(QString("|==================================================\n"));

			//	(7)指向二级目录中的资源目录项
			PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirectoryEntry_Sec = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)ResourceDirectory_Sec + sizeof(IMAGE_RESOURCE_DIRECTORY));

			//	(8)循环打印二级目录
			for (int j = 0; j < (ResourceDirectory_Sec->NumberOfIdEntries + ResourceDirectory_Sec->NumberOfNamedEntries); j++)
			{
				//	(9)判断二级目录中的资源目录项中编号是否是字符串
				if (ResourceDirectoryEntry_Sec->NameIsString) //字符串(非标准类型)
				{
					//		1.指向名字结构体
					PIMAGE_RESOURCE_DIR_STRING_U pStringName = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Sec->NameOffset);

					//		2.将Unicode字符串转换成ASCII字符串
					CHAR TypeName[20] = { 0 };
					for (int k = 0; k < pStringName->Length; k++)
					{
						TypeName[k] = (CHAR)pStringName->NameString[k];
					}
					//		3.打印字符串
					Final_Str.append(QString("    |ResourceNumber         :\"%1\"\n").arg(TypeName));
					// printf("    |ResourceNumber         :\"%s\"\n", TypeName);
				}
				else //非字符串(标准类型)
				{
					Final_Str.append(QString("    |ResourceNumber         :%1\n").arg(ResourceDirectoryEntry_Sec->Id, 4, 16));
					// printf("    |ResourceNumber         :%04X\n", ResourceDirectoryEntry_Sec->Id);

				}
				//	(10)判断二级目录中子节点的类型
				if (ResourceDirectoryEntry_Sec->DataIsDirectory)
				{
					//	(11)打印目录偏移
					Final_Str.append(QString("    |OffsetToDirectory      :%1\n").arg(ResourceDirectoryEntry_Sec->OffsetToDirectory, 8, 16));
					// printf("    |OffsetToDirectory      :%08X\n", ResourceDirectoryEntry_Sec->OffsetToDirectory);
					Final_Str.append(QString("|----------------------------------------\n"));
					// printf("    |------------------------------------\n");

					//	(12)指向三级目录	代码页
					PIMAGE_RESOURCE_DIRECTORY ResourceDirectory_Thir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Sec->OffsetToDirectory);

					//	(13)打印资源表信息(三级目录)
					//printf("        |================================\n");
					Final_Str.append(QString("|==================================================\n"));

					Final_Str.append(QString("|resources table 3rd index:\n"));
					// printf("|资源表一级目录信息:\n");
					Final_Str.append(QString("|Characteristics        	:%1\n").arg(ResourceDirectory_Thir->Characteristics, 8, 16));
					Final_Str.append(QString("|TimeDateStamp        	:%1\n").arg(ResourceDirectory_Thir->TimeDateStamp, 8, 16));
					Final_Str.append(QString("|MajorVersion        		:%1\n").arg(ResourceDirectory_Thir->MajorVersion, 4, 16));
					Final_Str.append(QString("|MinorVersion        		:%1\n").arg(ResourceDirectory_Thir->MinorVersion, 4, 16));
					Final_Str.append(QString("|NumberOfNamedEntries     :%1\n").arg(ResourceDirectory_Thir->NumberOfNamedEntries, 4, 16));
					Final_Str.append(QString("|NumberOfIdEntries        :%1\n").arg(ResourceDirectory_Thir->NumberOfIdEntries, 4, 16));
					// printf("        |资源表三级目录信息:\n");
					// printf("        |Characteristics        :%08X\n", ResourceDirectory_Thir->Characteristics);
					// printf("        |TimeDateStamp          :%08X\n", ResourceDirectory_Thir->TimeDateStamp);
					// printf("        |MajorVersion           :%04X\n", ResourceDirectory_Thir->MajorVersion);
					// printf("        |MinorVersion           :%04X\n", ResourceDirectory_Thir->MinorVersion);
					// printf("        |NumberOfNamedEntries   :%04X\n", ResourceDirectory_Thir->NumberOfNamedEntries);
					// printf("        |NumberOfIdEntries      :%04X\n", ResourceDirectory_Thir->NumberOfIdEntries);
					//printf("        |================================\n");
					Final_Str.append(QString("|==================================================\n"));

					//	(14)指向三级目录中的资源目录项
					PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirectoryEntry_Thir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)ResourceDirectory_Thir + sizeof(IMAGE_RESOURCE_DIRECTORY));

					//	(15)循环打印三级目录项
					for (int k = 0; k < (ResourceDirectory_Thir->NumberOfNamedEntries + ResourceDirectory_Thir->NumberOfIdEntries); k++)
					{
						//	(16)判断三级目录中的资源目录项中编号是否是字符串
						if (ResourceDirectoryEntry_Thir->NameIsString) //字符串(非标准类型)
						{
							//		1.指向名字结构体
							PIMAGE_RESOURCE_DIR_STRING_U pStringName = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Thir->NameOffset);

							//		2.将Unicode字符串转换成ASCII字符串
							CHAR TypeName[20] = { 0 };
							for (int k = 0; k < pStringName->Length; k++)
							{
								TypeName[k] = (CHAR)pStringName->NameString[k];
							}
							//		3.打印字符串
							Final_Str.append(QString("        |CodePageNumber         :\"%1\"\n").arg(TypeName));
							// printf("        |CodePageNumber         :\"%s\"\n", TypeName);
						}
						else //非字符串(标准类型)
						{
							Final_Str.append(QString("        |CodePageNumber         :\"%1\"\n").arg(ResourceDirectoryEntry_Thir->Id, 4, 16));
							//printf("        |CodePageNumber         :%04Xh\n", ResourceDirectoryEntry_Thir->Id);
						}
						//	(17)判断三级目录中子节点的类型		(三级目录子节点都是数据，这里可以省去判断)
						if (ResourceDirectoryEntry_Thir->DataIsDirectory)
						{
							//	(18)打印偏移
							Final_Str.append(QString("        |OffsetToDirectory      :%1\n").arg(ResourceDirectoryEntry_Thir->OffsetToDirectory, 8, 16));
							// printf("        |OffsetToDirectory      :%08X\n", ResourceDirectoryEntry_Thir->OffsetToDirectory);
							//printf("        |------------------------------------\n");
							Final_Str.append(QString("|----------------------------------------\n"));
						}
						else
						{
							//	(18)打印偏移
							Final_Str.append(QString("        |OffsetToData           :%1\n").arg(ResourceDirectoryEntry_Thir->OffsetToData, 8, 16));
							//printf("        |OffsetToData           :%08X\n", ResourceDirectoryEntry_Thir->OffsetToData);
							//printf("        |------------------------------------\n");
							Final_Str.append(QString("|----------------------------------------\n"));

							//	(19)指向数据内容	(资源表的FOA + OffsetToData)
							PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Thir->OffsetToData);

							//	(20)打印数据信息
							Final_Str.append(QString("            |================================\n"));
							Final_Str.append(QString("            |resources' data info\n"));
							Final_Str.append(QString("            |OffsetToData(RVA)      :%1\n").arg(ResourceDataEntry->OffsetToData, 8, 16));
							Final_Str.append(QString("            |size                   :%1\n").arg(ResourceDataEntry->Size, 8, 16));
							Final_Str.append(QString("            |CodePage               :%1\n").arg(ResourceDataEntry->CodePage, 8, 16));
							Final_Str.append(QString("            |================================\n"));
							// printf("            |================================\n");
							// printf("            |资源表的数据信息\n");
							// printf("            |OffsetToData(RVA)      :%08X\n", ResourceDataEntry->OffsetToData);
							// printf("            |Size                   :%08X\n", ResourceDataEntry->Size);
							// printf("            |CodePage               :%08X\n", ResourceDataEntry->CodePage);
							// printf("            |================================\n");
						}

						ResourceDirectoryEntry_Thir++;
					}
				}
				//	(21)目录项后移
				ResourceDirectoryEntry_Sec++;
			}
		}
		//printf("|----------------------------------------\n");
		Final_Str.append(QString("|----------------------------------------\n"));
		//	(22)目录项后移
		ResourceDirectoryEntry++;
	}
	return ret;
}

int PrintResourceTable_64_info(PVOID FileAddress)
{
	/*string szResType[0x11] = { 0, "鼠标指针", "位图", "图标", "菜单",
						 "对话框", "字符串列表", "字体目录", "字体",
						 "加速键", "非格式化资源", "消息列表", "鼠标指针组",
						 "zz", "图标组", "xx", "版本信息" };
	*/
	int szResType[17] = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
		'9', '10', '11', '12', '13', '14', '15', '16' };

	int ret = 0;
	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2、获取资源表的地址
	DWORD ResourceDirectory_RVAAdd = pOptionalHeader->DataDirectory[2].VirtualAddress;
	DWORD ResourceDirectory_FOAAdd = 0;
	//	(1)、判断资源表是否存在
	if (ResourceDirectory_RVAAdd == 0)
	{
		//printf("ResourceDirectory 不存在!\n");
		Final_Str.append(QString("ResourceDirectory not exists!\n"));
		return ret;
	}
	//	(2)、获取资源表的FOA地址
	ret = RVA_TO_FOA_info(FileAddress, ResourceDirectory_RVAAdd, &ResourceDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA_info() Error!\n");
		return ret;
	}

	//3、指向资源表
	PIMAGE_RESOURCE_DIRECTORY ResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)FileAddress + ResourceDirectory_FOAAdd);

	//4、打印资源表信息(一级目录)
	Final_Str.append(QString("|==================================================\n"));
	// printf("|==================================================\n");
	Final_Str.append(QString("|resources table 1st index:\n"));
	// printf("|资源表一级目录信息:\n");
	Final_Str.append(QString("|Characteristics        	:%1\n").arg(ResourceDirectory->Characteristics, 8, 16));
	Final_Str.append(QString("|TimeDateStamp        	:%1\n").arg(ResourceDirectory->TimeDateStamp, 8, 16));
	Final_Str.append(QString("|MajorVersion        		:%1\n").arg(ResourceDirectory->MajorVersion, 4, 16));
	Final_Str.append(QString("|MinorVersion        		:%1\n").arg(ResourceDirectory->MinorVersion, 4, 16));
	Final_Str.append(QString("|NumberOfNamedEntries     :%1\n").arg(ResourceDirectory->NumberOfNamedEntries, 4, 16));
	Final_Str.append(QString("|NumberOfIdEntries        :%1\n").arg(ResourceDirectory->NumberOfIdEntries, 4, 16));
	Final_Str.append(QString("|==================================================\n"));
	// printf("|==================================================\n");
	// printf("|资源表一级目录信息:\n");
	// printf("|Characteristics        :%08X\n", ResourceDirectory->Characteristics);
	// printf("|TimeDateStamp          :%08X\n", ResourceDirectory->TimeDateStamp);
	// printf("|MajorVersion           :%04X\n", ResourceDirectory->MajorVersion);
	// printf("|MinorVersion           :%04X\n", ResourceDirectory->MinorVersion);
	// printf("|NumberOfNamedEntries   :%04X\n", ResourceDirectory->NumberOfNamedEntries);
	// printf("|NumberOfIdEntries      :%04X\n", ResourceDirectory->NumberOfIdEntries);
	// printf("|==================================================\n");

	//4、循环打印后续资源表信息
	//	(1)指向一级目录中的资源目录项(一级目录)	资源类型
	PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirectoryEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)ResourceDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY));
	//printf("|----------------------------------------\n");
	Final_Str.append(QString("|----------------------------------------\n"));

	for (int i = 0; i < (ResourceDirectory->NumberOfIdEntries + ResourceDirectory->NumberOfNamedEntries); i++)
	{
		//	(2)判断一级目录中的资源目录项中类型是否是字符串 1 = 字符串(非标准类型)； 0 = 非字符串(标准类型)
		if (ResourceDirectoryEntry->NameIsString) //字符串(非标准类型)
		{
			//		1.指向名字结构体
			PIMAGE_RESOURCE_DIR_STRING_U pStringName = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)ResourceDirectory + ResourceDirectoryEntry->NameOffset);

			//		2.将Unicode字符串转换成ASCII字符串
			CHAR TypeName[20] = { 0 };
			for (int j = 0; j < pStringName->Length; j++)
			{
				TypeName[j] = (CHAR)pStringName->NameString[j];
			}
			//		3.打印字符串
			//printf("|ResourceType           :\"%s\"\n", TypeName);
			Final_Str.append(QString("|ResourceType           :\"%1\"\n").arg(TypeName));
		}
		else //非字符串(标准类型)
		{
			if (ResourceDirectoryEntry->Id < 0x11) //只有1 - 16有定义
				// printf("|ResourceType           :%d\n", szResType[ResourceDirectoryEntry->Id]);
				Final_Str.append(QString("|ResourceType           :\"%1\"\n").arg(szResType[ResourceDirectoryEntry->Id]));
			else
				// printf("|ResourceType           :%04Xh\n", ResourceDirectoryEntry->Id);
				Final_Str.append(QString("|ResourceType           :\"%1\"\n").arg(ResourceDirectoryEntry->Id, 4, 16));
		}

		//	(3)判断一级目录中子节点的类型		1 = 目录； 0 = 数据 (一级目录和二级目录该值都为1)
		if (ResourceDirectoryEntry->DataIsDirectory)
		{
			//	(4)打印目录偏移
			// printf("|OffsetToDirectory      :%08X\n", ResourceDirectoryEntry->OffsetToDirectory);
			Final_Str.append(QString("|OffsetToDirectory      :%1\n").arg(ResourceDirectoryEntry->OffsetToDirectory, 8, 16));
			// printf("|----------------------------------------\n");
			Final_Str.append(QString("|----------------------------------------\n"));

			//	(5)指向二级目录	资源编号
			PIMAGE_RESOURCE_DIRECTORY ResourceDirectory_Sec = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)ResourceDirectory + ResourceDirectoryEntry->OffsetToDirectory);

			//	(6)打印资源表信息(二级目录)
			Final_Str.append(QString("|==================================================\n"));
			Final_Str.append(QString("|resources table 2nd index:\n"));
			// printf("|资源表一级目录信息:\n");
			Final_Str.append(QString("|Characteristics        	:%1\n").arg(ResourceDirectory_Sec->Characteristics, 8, 16));
			Final_Str.append(QString("|TimeDateStamp        	:%1\n").arg(ResourceDirectory_Sec->TimeDateStamp, 8, 16));
			Final_Str.append(QString("|MajorVersion        		:%1\n").arg(ResourceDirectory_Sec->MajorVersion, 4, 16));
			Final_Str.append(QString("|MinorVersion        		:%1\n").arg(ResourceDirectory_Sec->MinorVersion, 4, 16));
			Final_Str.append(QString("|NumberOfNamedEntries     :%1\n").arg(ResourceDirectory_Sec->NumberOfNamedEntries, 4, 16));
			Final_Str.append(QString("|NumberOfIdEntries        :%1\n").arg(ResourceDirectory_Sec->NumberOfIdEntries, 4, 16));
			// printf("    |====================================\n");
			// printf("    |资源表二级目录信息:\n");
			// printf("    |Characteristics        :%08X\n", ResourceDirectory_Sec->Characteristics);
			// printf("    |TimeDateStamp          :%08X\n", ResourceDirectory_Sec->TimeDateStamp);
			// printf("    |MajorVersion           :%04X\n", ResourceDirectory_Sec->MajorVersion);
			// printf("    |MinorVersion           :%04X\n", ResourceDirectory_Sec->MinorVersion);
			// printf("    |NumberOfNamedEntries   :%04X\n", ResourceDirectory_Sec->NumberOfNamedEntries);
			// printf("    |NumberOfIdEntries      :%04X\n", ResourceDirectory_Sec->NumberOfIdEntries);
			// printf("    |====================================\n");

			//	(7)指向二级目录中的资源目录项
			PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirectoryEntry_Sec = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)ResourceDirectory_Sec + sizeof(IMAGE_RESOURCE_DIRECTORY));

			//	(8)循环打印二级目录
			for (int j = 0; j < (ResourceDirectory_Sec->NumberOfIdEntries + ResourceDirectory_Sec->NumberOfNamedEntries); j++)
			{
				//	(9)判断二级目录中的资源目录项中编号是否是字符串
				if (ResourceDirectoryEntry_Sec->NameIsString) //字符串(非标准类型)
				{
					//		1.指向名字结构体
					PIMAGE_RESOURCE_DIR_STRING_U pStringName = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Sec->NameOffset);

					//		2.将Unicode字符串转换成ASCII字符串
					CHAR TypeName[20] = { 0 };
					for (int k = 0; k < pStringName->Length; k++)
					{
						TypeName[k] = (CHAR)pStringName->NameString[k];
					}
					//		3.打印字符串
					// printf("    |ResourceNumber         :\"%s\"\n", TypeName);
					Final_Str.append(QString("    |ResourceNumber         :\"%1\"\n").arg(TypeName));
				}
				else //非字符串(标准类型)
				{
					// printf("    |ResourceNumber         :%04Xh\n", ResourceDirectoryEntry_Sec->Id);
					Final_Str.append(QString("    |ResourceNumber         :%1\n").arg(ResourceDirectoryEntry_Sec->Id, 4, 16));
				}
				//	(10)判断二级目录中子节点的类型
				if (ResourceDirectoryEntry_Sec->DataIsDirectory)
				{
					//	(11)打印目录偏移
					// printf("    |OffsetToDirectory      :%08X\n", ResourceDirectoryEntry_Sec->OffsetToDirectory);
					Final_Str.append(QString("    |OffsetToDirectory      :%1\n").arg(ResourceDirectoryEntry_Sec->OffsetToDirectory, 8, 16));
					//printf("    |------------------------------------\n");
					Final_Str.append(QString("|----------------------------------------\n"));

					//	(12)指向三级目录	代码页
					PIMAGE_RESOURCE_DIRECTORY ResourceDirectory_Thir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Sec->OffsetToDirectory);

					//	(13)打印资源表信息(三级目录)
					Final_Str.append(QString("|==================================================\n"));

					Final_Str.append(QString("|resources table 3rd index:\n"));
					// printf("|资源表三级目录信息:\n");
					Final_Str.append(QString("|Characteristics        	:%1\n").arg(ResourceDirectory_Thir->Characteristics, 8, 16));
					Final_Str.append(QString("|TimeDateStamp        	:%1\n").arg(ResourceDirectory_Thir->TimeDateStamp, 8, 16));
					Final_Str.append(QString("|MajorVersion        		:%1\n").arg(ResourceDirectory_Thir->MajorVersion, 4, 16));
					Final_Str.append(QString("|MinorVersion        		:%1\n").arg(ResourceDirectory_Thir->MinorVersion, 4, 16));
					Final_Str.append(QString("|NumberOfNamedEntries     :%1\n").arg(ResourceDirectory_Thir->NumberOfNamedEntries, 4, 16));
					Final_Str.append(QString("|NumberOfIdEntries        :%1\n").arg(ResourceDirectory_Thir->NumberOfIdEntries, 4, 16));
					// printf("        |================================\n");
					// printf("        |资源表三级目录信息:\n");
					// printf("        |Characteristics        :%08X\n", ResourceDirectory_Thir->Characteristics);
					// printf("        |TimeDateStamp          :%08X\n", ResourceDirectory_Thir->TimeDateStamp);
					// printf("        |MajorVersion           :%04X\n", ResourceDirectory_Thir->MajorVersion);
					// printf("        |MinorVersion           :%04X\n", ResourceDirectory_Thir->MinorVersion);
					// printf("        |NumberOfNamedEntries   :%04X\n", ResourceDirectory_Thir->NumberOfNamedEntries);
					// printf("        |NumberOfIdEntries      :%04X\n", ResourceDirectory_Thir->NumberOfIdEntries);
					// printf("        |================================\n");

					//	(14)指向三级目录中的资源目录项
					PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirectoryEntry_Thir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)ResourceDirectory_Thir + sizeof(IMAGE_RESOURCE_DIRECTORY));

					//	(15)循环打印三级目录项
					for (int k = 0; k < (ResourceDirectory_Thir->NumberOfNamedEntries + ResourceDirectory_Thir->NumberOfIdEntries); k++)
					{
						//	(16)判断三级目录中的资源目录项中编号是否是字符串
						if (ResourceDirectoryEntry_Thir->NameIsString) //字符串(非标准类型)
						{
							//		1.指向名字结构体
							PIMAGE_RESOURCE_DIR_STRING_U pStringName = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Thir->NameOffset);

							//		2.将Unicode字符串转换成ASCII字符串
							CHAR TypeName[20] = { 0 };
							for (int k = 0; k < pStringName->Length; k++)
							{
								TypeName[k] = (CHAR)pStringName->NameString[k];
							}
							//		3.打印字符串
							// printf("        |CodePageNumber         :\"%s\"\n", TypeName);
							Final_Str.append(QString("        |CodePageNumber         :\"%1\"\n").arg(TypeName));
						}
						else //非字符串(标准类型)
						{
							// printf("        |CodePageNumber         :%04Xh\n", ResourceDirectoryEntry_Thir->Id);
							Final_Str.append(QString("        |CodePageNumber         :\"%1\"\n").arg(ResourceDirectoryEntry_Thir->Id, 4, 16));
						}
						//	(17)判断三级目录中子节点的类型		(三级目录子节点都是数据，这里可以省去判断)
						if (ResourceDirectoryEntry_Thir->DataIsDirectory)
						{
							//	(18)打印偏移
							// printf("        |OffsetToDirectory      :%08X\n", ResourceDirectoryEntry_Thir->OffsetToDirectory);
							Final_Str.append(QString("        |OffsetToDirectory      :%1\n").arg(ResourceDirectoryEntry_Thir->OffsetToDirectory, 8, 16));
							//printf("        |------------------------------------\n");
							Final_Str.append(QString("|----------------------------------------\n"));
						}
						else
						{
							//	(18)打印偏移
							// printf("        |OffsetToData           :%08X\n", ResourceDirectoryEntry_Thir->OffsetToData);
							Final_Str.append(QString("        |OffsetToData           :%1\n").arg(ResourceDirectoryEntry_Thir->OffsetToData, 8, 16));
							//printf("        |------------------------------------\n");
							Final_Str.append(QString("|----------------------------------------\n"));

							//	(19)指向数据内容	(资源表的FOA + OffsetToData)
							PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Thir->OffsetToData);

							//	(20)打印数据信息
							Final_Str.append(QString("            |================================\n"));
							Final_Str.append(QString("            |resources' data info\n"));
							Final_Str.append(QString("            |OffsetToData(RVA)      :%1\n").arg(ResourceDataEntry->OffsetToData, 8, 16));
							Final_Str.append(QString("            |size                   :%1\n").arg(ResourceDataEntry->Size, 8, 16));
							Final_Str.append(QString("            |CodePage               :%1\n").arg(ResourceDataEntry->CodePage, 8, 16));
							Final_Str.append(QString("            |================================\n"));
							// printf("            |================================\n");
							// printf("            |资源表的数据信息\n");
							// printf("            |OffsetToData(RVA)      :%08X\n", ResourceDataEntry->OffsetToData);
							// printf("            |Size                   :%08X\n", ResourceDataEntry->Size);
							// printf("            |CodePage               :%08X\n", ResourceDataEntry->CodePage);
							// printf("            |================================\n");
						}

						ResourceDirectoryEntry_Thir++;
					}
				}
				//	(21)目录项后移
				ResourceDirectoryEntry_Sec++;
			}
		}
		//printf("|----------------------------------------\n");
		Final_Str.append(QString("|----------------------------------------\n"));
		//	(22)目录项后移
		ResourceDirectoryEntry++;
	}
	return ret;
}

/*
	异常表
*/
int PrintExceptionTable_info(PVOID FileAddress)
{
	int ret = 0;

	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2、获表的地址
	DWORD ExceptionDirectory_RAVAdd = pOptionalHeader->DataDirectory[3].VirtualAddress;
	DWORD ExceptionDirectory_FOAAdd = 0;
	DWORD ExceptionDirectory_size = pOptionalHeader->DataDirectory[3].Size;

	//	(1)、判断表是否存在
	if (ExceptionDirectory_RAVAdd == 0)
	{
		Final_Str.append(QString("ExceptionDirectory not exists!\n"));
		// printf("ExceptionDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取表的FOA地址
	ret = RVA_TO_FOA_info(FileAddress, ExceptionDirectory_RAVAdd, &ExceptionDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA_info() Error!\n");
		return ret;
	}
	//3、指向表
	PEXCEPTION_RECORD32 ExceptionRecord = (PEXCEPTION_RECORD32)((DWORD)FileAddress + ExceptionDirectory_FOAAdd);

	//4、打印信息 
	/*
	DWORD    ExceptionCode;
	DWORD ExceptionFlags;
	DWORD ExceptionRecord;
	DWORD ExceptionAddress;
	DWORD NumberParameters;
	DWORD ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
	*/
	Final_Str.append(QString("ExceptionDirectoryRVA		  :%1\n").arg(ExceptionDirectory_RAVAdd, 8, 16));
	Final_Str.append(QString("ExceptionDirectorySize		  :%1\n").arg(ExceptionDirectory_size, 8, 16));
	Final_Str.append(QString("================ Exception Record Start ======================\n"));
	Final_Str.append(QString("ExceptionCode				:%1\n").arg(ExceptionRecord->ExceptionCode, 8, 16));
	Final_Str.append(QString("ExceptionFlags		 	:%1\n").arg(ExceptionRecord->ExceptionFlags, 8, 16));
	Final_Str.append(QString("ExceptionRecord		  	:%1\n").arg(ExceptionRecord->ExceptionRecord, 8, 16));
	Final_Str.append(QString("ExceptionAddress		  	:%1\n").arg(ExceptionRecord->ExceptionAddress, 8, 16));
	Final_Str.append(QString("NumberParameters		  	:%1\n").arg(ExceptionRecord->NumberParameters, 8, 16));
	Final_Str.append(QString("ExceptionInformation		:%1\n").arg(*ExceptionRecord->ExceptionInformation));
	Final_Str.append(QString("================ Exception Record End ======================\n"));
	// printf("ExceptionDirectoryRVA		  :%08X\n", ExceptionDirectory_RAVAdd);
	// printf("ExceptionDirectorySize		  :%08X\n", ExceptionDirectory_size);
	// printf("================ Exception Record Start ======================\n");
	// printf("ExceptionCode				  :%08X\n", ExceptionRecord->ExceptionCode);
	// printf("ExceptionFlags				  :%08X\n", ExceptionRecord->ExceptionFlags);
	// printf("ExceptionRecord				  :%08X\n", ExceptionRecord->ExceptionRecord);
	// printf("ExceptionAddress		      :%08X\n", ExceptionRecord->ExceptionAddress);
	// printf("NumberParameters			  :%08X\n", ExceptionRecord->NumberParameters);
	// printf("ExceptionInformation		  :%s\n", ExceptionRecord->ExceptionInformation);
	// printf("================= Exception Record End ========================\n");

	return ret;
}

int PrintExceptionTable_64_info(PVOID FileAddress)
{
	int ret = 0;

	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2、获表的地址
	DWORD ExceptionDirectory_RAVAdd = pOptionalHeader->DataDirectory[3].VirtualAddress;
	DWORD ExceptionDirectory_FOAAdd = 0;
	DWORD ExceptionDirectory_size = pOptionalHeader->DataDirectory[3].Size;

	//	(1)、判断表是否存在
	if (ExceptionDirectory_RAVAdd == 0)
	{
		Final_Str.append(QString("ExceptionDirectory not exists!\n"));
		// printf("ExceptionDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取表的FOA地址
	ret = RVA_TO_FOA_info(FileAddress, ExceptionDirectory_RAVAdd, &ExceptionDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA_info() Error!\n");
		return ret;
	}
	//3、指向表
	PEXCEPTION_RECORD64 ExceptionRecord = (PEXCEPTION_RECORD64)((DWORD)FileAddress + ExceptionDirectory_FOAAdd);

	//4、打印信息 
	/*
	DWORD    ExceptionCode;
	DWORD ExceptionFlags;
	DWORD64 ExceptionRecord;
	DWORD64 ExceptionAddress;
	DWORD NumberParameters;
	DWORD __unusedAlignment;
	DWORD64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
	*/
	Final_Str.append(QString("ExceptionDirectoryRVA			:%1\n").arg(ExceptionDirectory_RAVAdd, 8, 16));
	Final_Str.append(QString("ExceptionDirectorySize		:%1\n").arg(ExceptionDirectory_size, 8, 16));
	Final_Str.append(QString("================ Exception Record Start ======================\n"));
	Final_Str.append(QString("ExceptionCode				:%1\n").arg(ExceptionRecord->ExceptionCode, 8, 16));
	Final_Str.append(QString("ExceptionFlags		 	:%1\n").arg(ExceptionRecord->ExceptionFlags, 8, 16));
	Final_Str.append(QString("ExceptionRecord		  	:%1\n").arg(ExceptionRecord->ExceptionRecord, 16, 16));
	Final_Str.append(QString("ExceptionAddress		  	:%1\n").arg(ExceptionRecord->ExceptionAddress, 16, 16));
	Final_Str.append(QString("NumberParameters		  	:%1\n").arg(ExceptionRecord->NumberParameters, 8, 16));
	Final_Str.append(QString("__unusedAlignment		  	:%1\n").arg(ExceptionRecord->__unusedAlignment, 8, 16));
	Final_Str.append(QString("ExceptionInformation		:%1\n").arg(*ExceptionRecord->ExceptionInformation));
	Final_Str.append(QString("================ Exception Record End ======================\n"));
	// printf("ExceptionDirectoryRVA		  :%08X\n", ExceptionDirectory_RAVAdd);
	// printf("ExceptionDirectorySize		  :%08X\n", ExceptionDirectory_size);
	// printf("================ Exception Record Start ======================\n");
	// printf("ExceptionCode		   :%08X\n", ExceptionRecord->ExceptionCode);
	// printf("ExceptionFlags         :%08X\n", ExceptionRecord->ExceptionFlags);
	// printf("ExceptionRecord		   :%16X\n", ExceptionRecord->ExceptionRecord);
	// printf("ExceptionAddress       :%16X\n", ExceptionRecord->ExceptionAddress);
	// printf("NumberParameters       :%08X\n", ExceptionRecord->NumberParameters);
	// printf("__unusedAlignment      :%08X\n", ExceptionRecord->__unusedAlignment);
	// printf("ExceptionInformation   :%s\n", ExceptionRecord->ExceptionInformation);
	// printf("================= Exception Record End ========================\n");

	return ret;
}

/*
	证书表(未完)
*/
int PrintReadSecurityTable_info(PVOID FileAddress)
{
	int ret = 0;

	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2、获取证书表的地址
	DWORD SecurityDirectory_RAVAdd = pOptionalHeader->DataDirectory[3].VirtualAddress;
	DWORD SecurityDirectory_FOAAdd = 0;

	//	(1)、判断证书表是否存在
	if (SecurityDirectory_RAVAdd == 0)
	{
		Final_Str.append(QString("SecurityDirectory not exists!\n"));
		//printf("SecurityDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取证书表的FOA地址
	ret = RVA_TO_FOA_info(FileAddress, SecurityDirectory_RAVAdd, &SecurityDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA_info() Error!\n");
		return ret;
	}
	//3、指向证书表
	//PIMAGE_BASE_RELOCATION SecurityDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)FileAddress + SecurityDirectory_FOAAdd);

	//4、循环打印证书信息  当VirtualAddress和SizeOfBlock都为0时遍历完成


	return ret;
}
int PrintReadSecurityTable_64_info(PVOID FileAddress)
{
	int ret = 0;
	return ret;
}
QString pError_info(int num)
{
	QString tmp;
	if (num == 0) {
		tmp = "Read success!\n";
	}
	else {
		tmp = "Read failed!\n";
	}
	return tmp;
}

QString peinfo(QString filePath)
{
	int ret = 0, ret_tmp = 0;
	PVOID FileAddress = NULL;

	//1、将文件读入到内存   
	ret = MyReadFile_info(&FileAddress, (PCHAR)filePath.toLatin1().data());
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return pError_info(ret);
	}
	//checkFile_info
	ret = checkFile_info(FileAddress);
	//32位程序
	if (ret == 32) {
		//2、打印导入表信息
		ret_tmp = PrintImportTable_info(FileAddress);
		if (ret_tmp != 0)
		{
			if (FileAddress != NULL)
				free(FileAddress);
			return pError_info(ret_tmp);
		}
		Final_Str.append(QString("\n"));
		//printf("\n");
		//3、输出表
		ret_tmp = PrintExportTable_info(FileAddress);
		if (ret_tmp != 0)
		{
			if (FileAddress != NULL)
				free(FileAddress);
			return pError_info(ret_tmp);
		}
		Final_Str.append(QString("\n"));
		//printf("\n");
		//4、打印重定位表信息
		ret_tmp = PrintReloactionTable_info(FileAddress);
		if (ret_tmp != 0)
		{
			if (FileAddress != NULL)
				free(FileAddress);
			return pError_info(ret_tmp);
		}
		Final_Str.append(QString("\n"));
		//printf("\n");
		//5、打印资源表的信息
		ret_tmp = PrintResourceTable_info(FileAddress);
		if (ret_tmp != 0)
		{
			if (FileAddress != NULL)
				free(FileAddress);
			return pError_info(ret_tmp);
		}
		Final_Str.append(QString("\n"));
		//printf("\n");
		//6、打印异常表的信息
		ret_tmp = PrintExceptionTable_info(FileAddress);
		if (ret_tmp != 0)
		{
			if (FileAddress != NULL)
				free(FileAddress);
			return pError_info(ret_tmp);
		}
	}
	else if (ret == 64) {
		//64位程序
		//2、打印导入表信息64位
		ret_tmp = PrintImportTable_64_info(FileAddress);
		if (ret_tmp != 0)
		{
			if (FileAddress != NULL)
				free(FileAddress);
			return pError_info(ret_tmp);
		}
		Final_Str.append(QString("\n"));
		//printf("\n");
		//3、打印导出表信息64位
		ret_tmp = PrintExportTable_64_info(FileAddress);
		if (ret_tmp != 0)
		{
			if (FileAddress != NULL)
				free(FileAddress);
			return pError_info(ret_tmp);
		}
		Final_Str.append(QString("\n"));
		//printf("\n");
		//4、打印重定位表信息64位
		ret_tmp = PrintReloactionTable_64_info(FileAddress);
		if (ret_tmp != 0)
		{
			if (FileAddress != NULL)
				free(FileAddress);
			return pError_info(ret_tmp);
		}
		Final_Str.append(QString("\n"));
		//printf("\n");
		//5、打印资源表的信息
		ret_tmp = PrintResourceTable_64_info(FileAddress);
		if (ret_tmp != 0)
		{
			if (FileAddress != NULL)
				free(FileAddress);
			return pError_info(ret_tmp);
		}
		Final_Str.append(QString("\n"));
		//printf("\n");
		//6、打印异常表的信息
		ret_tmp = PrintExceptionTable_64_info(FileAddress);
		if (ret_tmp != 0)
		{
			if (FileAddress != NULL)
				free(FileAddress);
			return pError_info(ret_tmp);
		}
	}
	else {
		if (FileAddress != NULL)
			free(FileAddress);
		return pError_info(ret);
	}

	return pError_info(ret_tmp);
}
