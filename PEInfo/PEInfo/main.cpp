/*
	author: ls
*/

# define _CRT_SECURE_NO_WARNINGS
# include <QtCore/QCoreApplication>
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"
# include "string"
# include "qdebug.h"
#include <IMAGEHLP.H>
#pragma comment(lib, "ImageHlp.lib")

/*
1、定位导入表，并打印出导入表中的内容、同时打印出INT表和IAT表
*/

int PrintImportTable(PVOID FileAddress)
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
		printf("ImportDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取导入表的FOA地址
	ret = RVA_TO_FOA(FileAddress, ImportDirectory_RVAAdd, &ImportDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
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
		ret = RVA_TO_FOA(FileAddress, ImportNameAdd_RVA, &ImportNameAdd_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}
		PCHAR pImportName = (PCHAR)((DWORD)FileAddress + ImportNameAdd_FOA);

		printf("=========================ImportTable %s Start=============================\n", pImportName);
		printf("OriginalFirstThunk RVA:%08X\n", ImportDirectory->OriginalFirstThunk);

		//	(2)指向INT表
		DWORD OriginalFirstThunk_RVA = ImportDirectory->OriginalFirstThunk;
		DWORD OriginalFirstThunk_FOA = 0;
		ret = RVA_TO_FOA(FileAddress, OriginalFirstThunk_RVA, &OriginalFirstThunk_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
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
				printf("按序号导入: %08Xh -- %08dd\n", Original, Original);	//16进制 -- 10 进制
			}
			else	//名字导入
			{
				//	(5)获取函数名
				DWORD ImportNameAdd_RAV = *OriginalFirstThunk_INT;
				DWORD ImportNameAdd_FOA = 0;
				ret = RVA_TO_FOA(FileAddress, ImportNameAdd_RAV, &ImportNameAdd_FOA);
				if (ret != 0)
				{
					printf("func RVA_TO_FOA() Error!\n");
					return ret;
				}
				PIMAGE_IMPORT_BY_NAME ImportName = (PIMAGE_IMPORT_BY_NAME)((DWORD)FileAddress + ImportNameAdd_FOA);
				printf("按名字导入[HINT/NAME]: %02X--%s\n", ImportName->Hint, ImportName->Name);
			}

			//	(6)指向下一个地址
			OriginalFirstThunk_INT++;
		}
		printf("----------------------------------------------------------------\n");
		printf("FirstThunk RVA   :%08X\n", ImportDirectory->FirstThunk);
		printf("TimeDateStamp    :%08X\n", ImportDirectory->TimeDateStamp);

		//	(2)指向IAT表
		DWORD FirstThunk_RVA = ImportDirectory->FirstThunk;
		DWORD FirstThunk_FOA = 0;
		ret = RVA_TO_FOA(FileAddress, FirstThunk_RVA, &FirstThunk_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}
		PDWORD FirstThunk_IAT = (PDWORD)((DWORD)FileAddress + FirstThunk_FOA);

		//	(3)判断IAT表是否被绑定	时间戳 = 0:没有绑定地址	时间戳 = 0xFFFFFFFF:绑定地址	——知识在绑定导入表中
		if (ImportDirectory->TimeDateStamp == 0xFFFFFFFF)
		{
			while (*FirstThunk_IAT)
			{
				printf("绑定函数地址: %08X\n", *FirstThunk_IAT);
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
					printf("按序号导入: %08Xh -- %08dd\n", Original, Original);	//16进制 -- 10 进制
				}
				else	//名字导入
				{
					//	(7)获取函数名
					DWORD ImportNameAdd_RAV = *FirstThunk_IAT;
					DWORD ImportNameAdd_FOA = 0;
					ret = RVA_TO_FOA(FileAddress, ImportNameAdd_RAV, &ImportNameAdd_FOA);
					if (ret != 0)
					{
						printf("func RVA_TO_FOA() Error!\n");
						return ret;
					}
					PIMAGE_IMPORT_BY_NAME ImportName = (PIMAGE_IMPORT_BY_NAME)((DWORD)FileAddress + ImportNameAdd_FOA);
					printf("按名字导入[HINT/NAME]: %02X--%s\n", ImportName->Hint, ImportName->Name);
				}

				FirstThunk_IAT++;
			}

		}

		printf("=========================ImportTable %s End  =============================\n", pImportName);

		//	(8)指向下一个导入表
		ImportDirectory++;
	}

	return ret;
}

/*
	读64位输入表
*/

int PrintImportTable_64(PVOID FileAddress)
{
	int ret = 0;
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
		printf("no import table!");
		return ret;
	}
	ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)ImageRvaToVa((PIMAGE_NT_HEADERS)pNTHeader64, pDosHeader, pNTHeader64->OptionalHeader.DataDirectory[1].VirtualAddress, NULL);
	printf("=================== import table start ===================\n");
	for (; ImportDirectory->Name != NULL;)
	{
		char* szName = (PSTR)ImageRvaToVa((PIMAGE_NT_HEADERS)pNTHeader64, pDosHeader, (ULONG)ImportDirectory->Name, 0);
		printf("%s\n", szName);
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
			printf("\t%0.4x\t%0.8x\t%s\n", Hint, dwThunk, szFun);
			dwThunk += 8;
			_pThunk++;
		}
		ImportDirectory++;
	}
	printf("=================== import table end ===================\n");
	return ret;
}



/*
	读64位pe输出表
*/
int PrintExportTable_64(PVOID FileAddress)
{
	int ret = 0;
	//1.指向相关内容
	PIMAGE_NT_HEADERS64 pNTHeader64;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	pDosHeader = (PIMAGE_DOS_HEADER)FileAddress;
	pNTHeader64 = (PIMAGE_NT_HEADERS64)((DWORD)FileAddress + pDosHeader->e_lfanew);

	if (pNTHeader64->OptionalHeader.DataDirectory[0].VirtualAddress == 0)
	{
		printf("no export table!");
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
	printf("=================== export table start ===================\n");
	for (i = 0; i < NumberOfNames; i++)
	{
		printf("%0.4x\t%0.8x\t%s\n", i + pExportDirectory->Base, *AddressTable, szFun);
		//printf("%s\n", szFun);
		szFun = szFun + strlen(szFun) + 1;
		AddressTable++;
		/*if (i % 200 == 0 && i / 200 >= 1)
		{
			printf("{Press [ENTER] to continue...}");
			getchar();
		}*/
	}
	printf("=================== export table end ===================\n");
	return ret;
}

// IAT
int PrintFunctionAddressTable(PVOID FileAddress, DWORD AddressOfFunctions_RVA, DWORD NumberOfFunctions)
{
	int ret = 0;
	DWORD AddressOfFunctions_FOA = 0;

	//1、RVA --> FOA
	ret = RVA_TO_FOA(FileAddress, AddressOfFunctions_RVA, &AddressOfFunctions_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//2、指向函数地址表
	PDWORD FuncAddressTable = (PDWORD)((DWORD)FileAddress + AddressOfFunctions_FOA);

	//2、循环打印函数地址表
	printf("=================== 函数地址表 Start ===================\n");
	for (DWORD i = 0; i < NumberOfFunctions; i++)
	{
		DWORD FuncAddress_RVA = FuncAddressTable[i];
		DWORD FuncAddress_FOA = 0;
		ret = RVA_TO_FOA(FileAddress, FuncAddress_RVA, &FuncAddress_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}

		printf("函数地址RVA    : %08X  |函数地址FOA    : %08X  \n", FuncAddress_RVA, FuncAddress_FOA);
	}
	printf("=================== 函数地址表 End   ===================\n\n");
	return ret;
}

//打印函数序号表
int PrintFunctionOrdinalTable(PVOID FileAddress, DWORD AddressOfOrdinal_RVA, DWORD NumberOfNames, DWORD Base)
{
	int ret = 0;
	DWORD AddressOfOrdinal_FOA = 0;

	//1、RVA --> FOA
	ret = RVA_TO_FOA(FileAddress, AddressOfOrdinal_RVA, &AddressOfOrdinal_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//2、指向函数序号表
	PWORD OrdinalTable = (PWORD)((DWORD)FileAddress + AddressOfOrdinal_FOA);

	//3、循环打印函数序号表
	printf("=================== 函数序号表 Start ===================\n");
	for (DWORD i = 0; i < NumberOfNames; i++)
	{
		printf("函数序号  :%04X  |Base+Ordinal   :%04X\n", OrdinalTable[i], OrdinalTable[i] + Base);
	}
	printf("=================== 函数序号表 End   ===================\n\n");
	return ret;
}

//打印函数名字表
int PrintFunctionNameTable(PVOID FileAddress, DWORD AddressOfNames_RVA, DWORD NumberOfNames)
{
	int ret = 0;
	DWORD AddressOfNames_FOA = 0;

	//1、RVA --> FOA
	ret = RVA_TO_FOA(FileAddress, AddressOfNames_RVA, &AddressOfNames_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//2、指向函数名表
	PDWORD NameTable = (PDWORD)((DWORD)FileAddress + AddressOfNames_FOA);

	//3、循环打印函数序号表
	printf("=================== 函数名表 Start ===================\n");
	for (DWORD i = 0; i < NumberOfNames; i++)
	{
		DWORD FuncName_RVA = NameTable[i];
		DWORD FuncName_FOA = 0;
		ret = RVA_TO_FOA(FileAddress, FuncName_RVA, &FuncName_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}
		PCHAR FuncName = (PCHAR)((DWORD)FileAddress + FuncName_FOA);

		printf("函数名  :%s\n", FuncName);
	}
	printf("=================== 函数名表 End   ===================\n\n");

	return ret;
}

/*
	输出表
*/

int PrintExportTable(PVOID FileAddress)
{
	int ret = 0;

	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	printf("%02X\n", pOptionalHeader->Magic);
	//2、获取导出表的地址
	DWORD ExportDirectory_RAVAdd = pOptionalHeader->DataDirectory[0].VirtualAddress;
	DWORD ExportDirectory_FOAAdd = 0;
	//	(1)、判断导出表是否存在
	if (ExportDirectory_RAVAdd == 0)
	{
		printf("ExportDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取导出表的FOA地址
	ret = RVA_TO_FOA(FileAddress, ExportDirectory_RAVAdd, &ExportDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//3、指向导出表
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)FileAddress + ExportDirectory_FOAAdd);

	//4、找到文件名
	DWORD FileName_RVA = ExportDirectory->Name;
	DWORD FileName_FOA = 0;
	ret = RVA_TO_FOA(FileAddress, FileName_RVA, &FileName_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}
	PCHAR FileName = (PCHAR)((DWORD)FileAddress + FileName_FOA);

	//5、打印导出表信息
	printf("*********************************************************\n");
	printf("=======================ExportTable=======================\n");
	printf("DWORD Characteristics;        :  %08X\n", ExportDirectory->Characteristics);
	printf("DWORD TimeDateStamp;          :  %08X\n", ExportDirectory->TimeDateStamp);
	printf("WORD  MajorVersion;           :  %04X\n", ExportDirectory->MajorVersion);
	printf("WORD  MinorVersion;           :  %04X\n", ExportDirectory->MinorVersion);
	printf("DWORD Name;                   :  %08X     \"%s\"\n", ExportDirectory->Name, FileName);
	printf("DWORD Base;                   :  %08X\n", ExportDirectory->Base);
	printf("DWORD NumberOfFunctions;      :  %08X\n", ExportDirectory->NumberOfFunctions);
	printf("DWORD NumberOfNames;          :  %08X\n", ExportDirectory->NumberOfNames);
	printf("DWORD AddressOfFunctions;     :  %08X\n", ExportDirectory->AddressOfFunctions);
	printf("DWORD AddressOfNames;         :  %08X\n", ExportDirectory->AddressOfNames);
	printf("DWORD AddressOfNameOrdinals;  :  %08X\n", ExportDirectory->AddressOfNameOrdinals);
	printf("=========================================================\n");
	printf("*********************************************************\n");

	//6、打印函数地址表 数量由NumberOfFunctions决定
	ret = PrintFunctionAddressTable(FileAddress, ExportDirectory->AddressOfFunctions, ExportDirectory->NumberOfFunctions);
	if (ret != 0)
	{
		printf("func PrintFunctionAddressTable() Error!\n");
		return ret;
	}

	//7、打印函数序号表 数量由NumberOfNames决定
	ret = PrintFunctionOrdinalTable(FileAddress, ExportDirectory->AddressOfNameOrdinals, ExportDirectory->NumberOfNames, ExportDirectory->Base);
	if (ret != 0)
	{
		printf("func PrintFunctionOrdinalTable() Error!\n");
		return ret;
	}

	//8、打印函数名表 数量由NumberOfNames决定
	ret = PrintFunctionNameTable(FileAddress, ExportDirectory->AddressOfNames, ExportDirectory->NumberOfNames);
	if (ret != 0)
	{
		printf("func PrintFunctionNameTable() Error!\n");
		return ret;
	}

	return ret;
}

/*
	重定位表
*/
int PrintReloactionTable(PVOID FileAddress)
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
		printf("RelocationDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取重定位表的FOA地址
	ret = RVA_TO_FOA(FileAddress, RelocationDirectory_RAVAdd, &RelocationDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//3、指向重定位表
	PIMAGE_BASE_RELOCATION RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)FileAddress + RelocationDirectory_FOAAdd);

	//4、循环打印重定位信息  当VirtualAddress和SizeOfBlock都为0时遍历完成
	while (RelocationDirectory->VirtualAddress && RelocationDirectory->SizeOfBlock)
	{
		printf("VirtualAddress    :%08X\n", RelocationDirectory->VirtualAddress);
		printf("SizeOfBlock       :%08X\n", RelocationDirectory->SizeOfBlock);
		printf("================= BlockData Start ======================\n");
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
				ret = RVA_TO_FOA(FileAddress, Data_RVA, &Data_FOA);
				if (ret != 0)
				{
					printf("func RVA_TO_FOA() Error!\n");
					return ret;
				}
				//(4)获取需要重定位的数据
				PDWORD RelocationData = (PDWORD)((DWORD)FileAddress + Data_FOA);

				printf("第[%04X]项    |数据 :[%04X]   |数据的RVA :[%08X]  |数据属性 :[%X]  |重定位数据  :[%08X]\n", i + 1, BlockData, Data_RVA, (DataGroup[i] >> 12), *RelocationData);
			}
		}
		printf("================= BlockData End ========================\n");

		//指向下一个数据块
		RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)RelocationDirectory + RelocationDirectory->SizeOfBlock);
	}
	return ret;
}

/*
	资源表
*/

int PrintResourceTable(PVOID FileAddress)
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
		printf("ResourceDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取资源表的FOA地址
	ret = RVA_TO_FOA(FileAddress, ResourceDirectory_RVAAdd, &ResourceDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//3、指向资源表
	PIMAGE_RESOURCE_DIRECTORY ResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)FileAddress + ResourceDirectory_FOAAdd);

	//4、打印资源表信息(一级目录)
	printf("|==================================================\n");
	printf("|资源表一级目录信息:\n");
	printf("|Characteristics        :%08X\n", ResourceDirectory->Characteristics);
	printf("|TimeDateStamp          :%08X\n", ResourceDirectory->TimeDateStamp);
	printf("|MajorVersion           :%04X\n", ResourceDirectory->MajorVersion);
	printf("|MinorVersion           :%04X\n", ResourceDirectory->MinorVersion);
	printf("|NumberOfNamedEntries   :%04X\n", ResourceDirectory->NumberOfNamedEntries);
	printf("|NumberOfIdEntries      :%04X\n", ResourceDirectory->NumberOfIdEntries);
	printf("|==================================================\n");

	//4、循环打印后续资源表信息
	//	(1)指向一级目录中的资源目录项(一级目录)	资源类型
	PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirectoryEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)ResourceDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY));
	printf("|----------------------------------------\n");

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
			printf("|ResourceType           :\"%s\"\n", TypeName);
		}
		else //非字符串(标准类型)
		{
			if (ResourceDirectoryEntry->Id < 0x11) //只有1 - 16有定义
				printf("|ResourceType           :%d\n", szResType[ResourceDirectoryEntry->Id]);
			else
				printf("|ResourceType           :%04Xh\n", ResourceDirectoryEntry->Id);
		}

		//	(3)判断一级目录中子节点的类型		1 = 目录； 0 = 数据 (一级目录和二级目录该值都为1)
		if (ResourceDirectoryEntry->DataIsDirectory)
		{
			//	(4)打印目录偏移
			printf("|OffsetToDirectory      :%08X\n", ResourceDirectoryEntry->OffsetToDirectory);
			printf("|----------------------------------------\n");

			//	(5)指向二级目录	资源编号
			PIMAGE_RESOURCE_DIRECTORY ResourceDirectory_Sec = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)ResourceDirectory + ResourceDirectoryEntry->OffsetToDirectory);

			//	(6)打印资源表信息(二级目录)
			printf("    |====================================\n");
			printf("    |资源表二级目录信息:\n");
			printf("    |Characteristics        :%08X\n", ResourceDirectory_Sec->Characteristics);
			printf("    |TimeDateStamp          :%08X\n", ResourceDirectory_Sec->TimeDateStamp);
			printf("    |MajorVersion           :%04X\n", ResourceDirectory_Sec->MajorVersion);
			printf("    |MinorVersion           :%04X\n", ResourceDirectory_Sec->MinorVersion);
			printf("    |NumberOfNamedEntries   :%04X\n", ResourceDirectory_Sec->NumberOfNamedEntries);
			printf("    |NumberOfIdEntries      :%04X\n", ResourceDirectory_Sec->NumberOfIdEntries);
			printf("    |====================================\n");

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
					printf("    |ResourceNumber         :\"%s\"\n", TypeName);
				}
				else //非字符串(标准类型)
				{
					printf("    |ResourceNumber         :%04Xh\n", ResourceDirectoryEntry_Sec->Id);
				}
				//	(10)判断二级目录中子节点的类型
				if (ResourceDirectoryEntry_Sec->DataIsDirectory)
				{
					//	(11)打印目录偏移
					printf("    |OffsetToDirectory      :%08X\n", ResourceDirectoryEntry_Sec->OffsetToDirectory);
					printf("    |------------------------------------\n");

					//	(12)指向三级目录	代码页
					PIMAGE_RESOURCE_DIRECTORY ResourceDirectory_Thir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Sec->OffsetToDirectory);

					//	(13)打印资源表信息(三级目录)
					printf("        |================================\n");
					printf("        |资源表三级目录信息:\n");
					printf("        |Characteristics        :%08X\n", ResourceDirectory_Thir->Characteristics);
					printf("        |TimeDateStamp          :%08X\n", ResourceDirectory_Thir->TimeDateStamp);
					printf("        |MajorVersion           :%04X\n", ResourceDirectory_Thir->MajorVersion);
					printf("        |MinorVersion           :%04X\n", ResourceDirectory_Thir->MinorVersion);
					printf("        |NumberOfNamedEntries   :%04X\n", ResourceDirectory_Thir->NumberOfNamedEntries);
					printf("        |NumberOfIdEntries      :%04X\n", ResourceDirectory_Thir->NumberOfIdEntries);
					printf("        |================================\n");

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
							printf("        |CodePageNumber         :\"%s\"\n", TypeName);
						}
						else //非字符串(标准类型)
						{
							printf("        |CodePageNumber         :%04Xh\n", ResourceDirectoryEntry_Thir->Id);
						}
						//	(17)判断三级目录中子节点的类型		(三级目录子节点都是数据，这里可以省去判断)
						if (ResourceDirectoryEntry_Thir->DataIsDirectory)
						{
							//	(18)打印偏移
							printf("        |OffsetToDirectory      :%08X\n", ResourceDirectoryEntry_Thir->OffsetToDirectory);
							printf("        |------------------------------------\n");
						}
						else
						{
							//	(18)打印偏移
							printf("        |OffsetToData           :%08X\n", ResourceDirectoryEntry_Thir->OffsetToData);
							printf("        |------------------------------------\n");

							//	(19)指向数据内容	(资源表的FOA + OffsetToData)
							PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Thir->OffsetToData);

							//	(20)打印数据信息
							printf("            |================================\n");
							printf("            |资源表的数据信息\n");
							printf("            |OffsetToData(RVA)      :%08X\n", ResourceDataEntry->OffsetToData);
							printf("            |Size                   :%08X\n", ResourceDataEntry->Size);
							printf("            |CodePage               :%08X\n", ResourceDataEntry->CodePage);
							printf("            |================================\n");
						}

						ResourceDirectoryEntry_Thir++;
					}
				}
				//	(21)目录项后移
				ResourceDirectoryEntry_Sec++;
			}
		}
		printf("|----------------------------------------\n");
		//	(22)目录项后移
		ResourceDirectoryEntry++;
	}
	return ret;
}


int main()
{
	int ret = 0;
	PVOID FileAddress = NULL;

	//1、将文件读入到内存   
	ret = MyReadFile(&FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//2、打印导入表信息64位
	ret = PrintImportTable_64(FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}
	qDebug() << "print done\n";
	//2、打印导出表信息64位
	/*ret = PrintExportTable_64(FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}*/
	//2、打印导入表信息
	/*ret = PrintImportTable(FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}*/

	//3、输出表
	/*ret = PrintExportTable(FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}*/

	//4、打印重定位表信息
	/*ret = PrintReloactionTable(FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}*/

	//5、打印资源表的信息
	/*ret = PrintResourceTable(FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}*/
	//checkFile
	ret = checkFile(FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}
	qDebug() << "check done\n";
	if (FileAddress != NULL)
		free(FileAddress);

	system("pause");
	return ret;
}
//异常表[3]
